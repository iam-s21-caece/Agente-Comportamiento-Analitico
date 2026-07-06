"""Bucle ReAct principal del agente.

Implementa el ciclo razonar -> invocar tool -> observar -> razonar, hasta que el
LLM emite la alerta final (tool ``emit_alert``) o se alcanza el límite de
iteraciones. Cada paso se loguea en detalle para análisis post-hoc (requisito de
la evaluación empírica de la tesis).
"""

from __future__ import annotations

import json
from typing import Any

from alert_builder.builder import AlertBuilder
from alert_builder.schema import Alert
from config.logging_config import get_logger
from config.settings import Settings, get_settings

from .llm_client import LLMClient
from .prompt_templates import SYSTEM_PROMPT, build_initial_context
from .tools import ToolRegistry
from traceability.trace_recorder import TraceRecorder

logger = get_logger(__name__)


class ReactLoop:
    """Orquesta el razonamiento ReAct sobre las tools y emite una ``Alert``."""

    def __init__(
        self,
        llm: LLMClient,
        tools: ToolRegistry,
        alert_builder: AlertBuilder,
        settings: Settings | None = None,
        recorder: TraceRecorder | None = None,
    ) -> None:
        """Inicializa el loop.

        Args:
            llm: cliente LLM a utilizar.
            tools: registro de tools disponibles.
            alert_builder: validador/constructor de la alerta final.
            settings: configuración opcional.
            recorder: registrador de trazabilidad (opcional). Si es ``None`` el
                loop se comporta exactamente igual que antes (capa observacional
                desacoplada, no altera la lógica del ReAct).
        """
        self.llm = llm
        self.tools = tools
        self.alert_builder = alert_builder
        self.settings = settings or get_settings()
        self.recorder = recorder
        # Id del análisis en curso, para correlacionar trazas.
        self._analysis_id: str | None = None

    def run(self, state_summary: str) -> Alert:
        """Ejecuta el bucle ReAct hasta obtener una alerta.

        Args:
            state_summary: resumen del estado observado que inicia el análisis.

        Returns:
            Alert validada. Si el LLM no emite alerta dentro del límite de
            iteraciones, se devuelve una alerta determinista de fallback.
        """
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": build_initial_context(state_summary)},
        ]
        tool_specs = self.tools.get_specs()

        # Inicio del análisis: id de correlación y traza del estado recibido.
        self._analysis_id = (
            self.recorder.new_analysis_id() if self.recorder else None
        )
        if self.recorder and self._analysis_id:
            self.recorder.start_analysis(self._analysis_id, state_summary)

        last_iteration = 0
        for iteration in range(1, self.settings.react_max_iterations + 1):
            last_iteration = iteration
            logger.info("ReAct iteración", extra={"iteration": iteration})
            if self.recorder and self._analysis_id:
                self.recorder.record_iteration(self._analysis_id, iteration)
            response = self.llm.chat(messages, tools=tool_specs)

            if response.content:
                logger.info(
                    "Razonamiento del LLM",
                    extra={"iteration": iteration, "thought": response.content[:2000]},
                )
                if self.recorder and self._analysis_id:
                    self.recorder.record_thought(
                        self._analysis_id, iteration, response.content
                    )

            if not response.wants_tools:
                # El LLM respondió sin pedir tools ni emitir alerta: lo empujamos
                # a usar emit_alert para cerrar el análisis correctamente.
                messages.append({"role": "assistant", "content": response.content})
                messages.append(
                    {
                        "role": "user",
                        "content": "Cerrá el análisis llamando a emit_alert con la "
                        "alerta estructurada.",
                    }
                )
                continue

            # Registrar el turno del asistente con sus tool_calls.
            messages.append(self._assistant_turn(response))

            for call in response.tool_calls:
                # NOTA: la clave del extra NO puede ser "args": colisiona con el
                # atributo reservado LogRecord.args y hace crashear el logging
                # ("Attempt to overwrite 'args' in LogRecord"). Usamos "tool_args".
                logger.info(
                    "Tool solicitada",
                    extra={
                        "iteration": iteration,
                        "tool": call.name,
                        "tool_args": call.arguments,
                    },
                )
                if self.recorder and self._analysis_id:
                    self.recorder.record_tool_call(
                        self._analysis_id, iteration, call.name, call.arguments
                    )
                result = self.tools.dispatch(call.name, call.arguments)
                if self.recorder and self._analysis_id:
                    self.recorder.record_tool_result(
                        self._analysis_id, iteration, call.name, result
                    )
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": call.id,
                        "content": json.dumps(result, ensure_ascii=False, default=str),
                    }
                )

            if self.tools.is_alert_emitted:
                return self._finalize(last_iteration)

        logger.warning("ReAct alcanzó el límite de iteraciones sin alerta")
        alert = self._fallback_alert()
        self._record_end(alert, last_iteration)
        return alert

    def _assistant_turn(self, response: Any) -> dict[str, Any]:
        """Serializa el turno del asistente (con tool_calls) para el historial.

        Args:
            response: ``LLMResponse`` con tool calls.

        Returns:
            Mensaje de rol ``assistant`` en formato OpenAI.
        """
        return {
            "role": "assistant",
            "content": response.content or None,
            "tool_calls": [
                {
                    "id": call.id,
                    "type": "function",
                    "function": {
                        "name": call.name,
                        "arguments": json.dumps(call.arguments, ensure_ascii=False),
                    },
                }
                for call in response.tool_calls
            ],
        }

    def _finalize(self, iteration: int) -> Alert:
        """Valida la alerta emitida por el LLM contra el esquema.

        Args:
            iteration: número de iteración en que se emitió la alerta.

        Returns:
            Alert validada, o fallback determinista si la validación falla.
        """
        payload = self.tools.ctx.emitted_alert or {}
        try:
            alert = self.alert_builder.from_llm_dict(payload)
            logger.info(
                "Alerta validada",
                extra={"alert_id": alert.alert_id, "severity": alert.severity},
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("Alerta del LLM inválida, usando fallback", extra={"error": str(exc)})
            if self.recorder and self._analysis_id:
                self.recorder.record_error(self._analysis_id, str(exc), where="_finalize")
            alert = self._fallback_alert()
        self._record_end(alert, iteration)
        return alert

    def _record_end(self, alert: Alert, iterations: int) -> None:
        """Registra en la traza la alerta final y el fin del análisis.

        Args:
            alert: alerta producida.
            iterations: iteraciones consumidas por el análisis.
        """
        if not (self.recorder and self._analysis_id):
            return
        self.recorder.record_alert(self._analysis_id, alert)
        self.recorder.end_analysis(self._analysis_id, iterations)

    def _fallback_alert(self) -> Alert:
        """Construye una alerta determinista desde los checks ya ejecutados.

        Returns:
            Alert generada sin LLM (puede quedar vacía si no hubo detecciones).
        """
        results = []
        for check in self.tools.ctx.checks.values():
            try:
                results.extend(check.run(**self.tools.ctx.check_inputs))
            except Exception:  # noqa: BLE001
                continue
        return self.alert_builder.from_check_results(results)
