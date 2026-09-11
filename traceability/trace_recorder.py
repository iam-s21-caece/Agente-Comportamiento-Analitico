"""Registro de trazabilidad del ciclo agéntico (capa observacional).

El ``TraceRecorder`` se engancha en los puntos clave del loop ReAct **sin
modificar su lógica**: solo observa. Registra el snapshot inicial, cada
iteración, el chain-of-thought del LLM, cada tool con sus inputs/outputs, cada
check determinista, la knowledge base consultada y la alerta final. Cada evento
lleva timestamp de alta precisión, id único y correlación con el análisis padre.

Regla de oro: **ningún método puede propagar excepciones** hacia el agente. Si el
registro falla, se loguea y el agente sigue funcionando.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field

from config.logging_config import get_logger
from config.settings import Settings, get_settings

from .audit_logger import AuditLogger
from .trace_store import TraceStore

logger = get_logger(__name__)

EventType = Literal[
    "analysis_start",
    "iteration",
    "llm_thought",
    "tool_call",
    "tool_result",
    "check_result",
    "kb_query",
    "alert_emitted",
    "analysis_end",
    "error",
]


def _now() -> datetime:
    """Instante actual en UTC con microsegundos (alta precisión)."""
    return datetime.now(timezone.utc)


class TraceEvent(BaseModel):
    """Un evento del ciclo agéntico, unidad de la traza."""

    analysis_id: str
    event_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    seq: int
    timestamp: datetime = Field(default_factory=_now)
    event_type: EventType
    payload: dict[str, Any] = Field(default_factory=dict)


class TraceRecorder:
    """Registra trazas del ciclo agéntico en el ``TraceStore`` y auditoría."""

    def __init__(
        self,
        settings: Settings | None = None,
        store: TraceStore | None = None,
        audit: AuditLogger | None = None,
    ) -> None:
        """Inicializa el recorder.

        Args:
            settings: configuración; si se omite se usa la global.
            store: store de trazas; si se omite se crea uno según settings.
            audit: logger de auditoría; si se omite se crea uno.
        """
        self.settings = settings or get_settings()
        self.store = store or TraceStore(
            self.settings.traces_dir, self.settings.trace_max_event_bytes
        )
        self.audit = audit or AuditLogger()
        # Contador de secuencia por análisis (orden de eventos).
        self._seq: dict[str, int] = {}

    # ---------------------------------------------------------- API pública
    def new_analysis_id(self) -> str:
        """Genera un ``analysis_id`` único para un nuevo análisis."""
        return f"an-{uuid.uuid4().hex[:16]}"

    def start_analysis(self, analysis_id: str, state_summary: str) -> None:
        """Registra el inicio de un análisis con el estado recibido."""
        self._emit(analysis_id, "analysis_start", {"state_summary": state_summary})

    def record_iteration(self, analysis_id: str, iteration: int) -> None:
        """Registra el inicio de una iteración del loop ReAct."""
        self._emit(analysis_id, "iteration", {"iteration": iteration})

    def record_thought(self, analysis_id: str, iteration: int, thought: str) -> None:
        """Registra el chain-of-thought del LLM en una iteración."""
        self._emit(
            analysis_id, "llm_thought", {"iteration": iteration, "thought": thought}
        )

    def record_tool_call(
        self, analysis_id: str, iteration: int, tool: str, args: dict[str, Any]
    ) -> None:
        """Registra una tool solicitada con sus argumentos."""
        self._emit(
            analysis_id,
            "tool_call",
            {"iteration": iteration, "tool": tool, "arguments": args},
        )

    def record_tool_result(
        self, analysis_id: str, iteration: int, tool: str, result: Any
    ) -> None:
        """Registra el resultado de una tool.

        Si la tool fue ``run_deterministic_check`` se etiqueta además como
        ``check_result`` para facilitar la consulta posterior.
        """
        event_type: EventType = (
            "check_result" if tool == "run_deterministic_check" else "tool_result"
        )
        self._emit(
            analysis_id,
            event_type,
            {"iteration": iteration, "tool": tool, "result": result},
        )

    def record_kb_query(self, analysis_id: str, cve_id: str, definition: Any) -> None:
        """Registra una consulta a la knowledge base."""
        self._emit(
            analysis_id, "kb_query", {"cve_id": cve_id, "definition": definition}
        )

    def record_alert(self, analysis_id: str, alert: Any) -> None:
        """Registra la alerta final emitida."""
        payload = alert.model_dump(mode="json") if hasattr(alert, "model_dump") else alert
        self._emit(analysis_id, "alert_emitted", {"alert": payload})

    def record_error(self, analysis_id: str, error: str, where: str = "") -> None:
        """Registra un error ocurrido durante el análisis."""
        self._emit(analysis_id, "error", {"error": error, "where": where})

    def end_analysis(
        self, analysis_id: str, iterations: int, usage: Any = None
    ) -> None:
        """Registra el fin de un análisis y libera el contador de secuencia.

        Args:
            analysis_id: id del análisis.
            iterations: iteraciones consumidas.
            usage: consumo de tokens del análisis (``llm_client.Usage`` o ``None``).
                Se persiste en la traza para habilitar las métricas de costo y de
                adherencia al presupuesto sin acoplar la validación al runtime.
        """
        payload: dict[str, Any] = {"iterations": iterations}
        if usage is not None:
            payload["tokens"] = {
                "prompt_tokens": getattr(usage, "prompt_tokens", 0),
                "completion_tokens": getattr(usage, "completion_tokens", 0),
                "total_tokens": getattr(usage, "total_tokens", 0),
                "cache_hit_tokens": getattr(usage, "cache_hit_tokens", 0),
                "cache_miss_tokens": getattr(usage, "cache_miss_tokens", 0),
            }
        self._emit(analysis_id, "analysis_end", payload)
        self._seq.pop(analysis_id, None)

    # ---------------------------------------------------------- internos
    def _next_seq(self, analysis_id: str) -> int:
        """Devuelve el próximo número de secuencia para un análisis."""
        seq = self._seq.get(analysis_id, 0)
        self._seq[analysis_id] = seq + 1
        return seq

    def _emit(
        self, analysis_id: str, event_type: EventType, payload: dict[str, Any]
    ) -> None:
        """Construye y persiste un evento; nunca propaga excepciones.

        Args:
            analysis_id: id del análisis padre.
            event_type: tipo de evento.
            payload: contenido específico del evento.
        """
        try:
            seq = self._next_seq(analysis_id)
            event = TraceEvent(
                analysis_id=analysis_id,
                seq=seq,
                event_type=event_type,
                payload=payload,
            )
            self.store.write(analysis_id, event.timestamp, event.model_dump(mode="json"))
            self.audit.event(analysis_id, event.event_id, event_type, seq)
        except Exception as exc:  # noqa: BLE001 - observación no debe romper el agente
            logger.warning(
                "Fallo registrando traza (se continúa)",
                extra={"event_type": event_type, "error": str(exc)},
            )
