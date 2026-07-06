"""Entry point del agente de análisis de seguridad para Keycloak.

Modos de operación (seleccionables por CLI):
  * ``oneshot``: captura un snapshot, ejecuta el análisis ReAct completo, emite
    una alerta y termina. Útil para evaluación reproducible.
  * ``continuous``: corre en loop capturando snapshots cada N segundos y mantiene
    una ventana deslizante de eventos, disparando el análisis ReAct cuando un
    check determinista detecta condiciones (o siempre, si ``always_analyze``).

La evaluación empírica (precision/recall, calidad, escenarios) vive en el módulo
``validation/`` y se ejecuta aparte con ``validation_cli.py`` — no se mezcla con
el runtime del agente.

Uso:
    python main.py --mode continuous
    python main.py --mode oneshot --no-llm
"""

from __future__ import annotations

import argparse
import json
import time
from collections import deque
from typing import Any

from agent_core.llm_client import DeepSeekClient, LLMClient
from agent_core.react_loop import ReactLoop
from agent_core.tools import AgentContext, ToolRegistry
from alert_builder.builder import AlertBuilder
from alert_builder.schema import Alert
from alert_builder.sink import AlertSink
from config.logging_config import get_logger, setup_logging
from config.settings import Settings, get_settings
from deterministic_checks.dos_thresholds import BaselineManager, DosThresholdCheck
from deterministic_checks.oidc_correlation import OidcCorrelationCheck
from knowledge_base.loader import KnowledgeBase, load_knowledge_base
from signal_collector.container_metrics import ContainerMetricsCollector
from signal_collector.host_metrics import HostMetricsCollector
from signal_collector.keycloak_events import KeycloakEventsCollector
from dashboard_server import start_dashboard_server
from traceability.trace_recorder import TraceRecorder

logger = get_logger(__name__)

_OIDC_EVENT_TYPES = ["LOGIN", "LOGOUT", "CODE_TO_TOKEN", "REFRESH_TOKEN"]


def compute_trigger_signature(triggered: list) -> str:
    """Construye una firma ESTABLE de las anomalías que dispararon un ciclo.

    Para OIDC usa el CONJUNTO (deduplicado) de ``session_id`` anómalos, de modo
    que la firma no cambie si el check reporta el mismo takeover con distinta
    cantidad de anomalías duplicadas entre ciclos (ese era el bug que hacía
    re-alertar). Para los demás checks usa el ``check_id`` (episodio).

    Args:
        triggered: checks que dispararon en el ciclo.

    Returns:
        Firma textual estable (vacía si no hay checks disparados).
    """
    parts: list[str] = []
    for result in triggered:
        if result.check_id == "oidc_session_reuse":
            # set -> deduplica; sorted -> orden estable.
            sids = sorted(
                {a.get("session_id", "") for a in result.evidence.get("anomalies", [])}
            )
            parts.append("oidc:" + ",".join(sids))
        else:
            parts.append(result.check_id)
    return "|".join(sorted(parts))


class SecurityAgent:
    """Orquestador del agente: arma dependencias y ejecuta los modos."""

    def __init__(self, settings: Settings, use_llm: bool = True) -> None:
        """Inicializa el agente y sus componentes.

        Args:
            settings: configuración del agente.
            use_llm: si ``False``, opera solo con checks deterministas (sin ReAct).
        """
        self.settings = settings
        self.use_llm = use_llm

        # Conocimiento (modelo del mundo).
        self.kb: KnowledgeBase = load_knowledge_base(settings.cves_dir)

        # Colectores de señales.
        self.host_collector = HostMetricsCollector(settings)
        self.container_collector = ContainerMetricsCollector(settings)
        self.events_collector = KeycloakEventsCollector(settings)

        # Baseline (modo híbrido) y checks deterministas.
        baseline = BaselineManager(settings, self.host_collector).load_or_build()
        dos_def = self.kb.get("CVE-2026-33871")
        oidc_def = self.kb.get("CVE-2023-0264")
        self.checks: dict[str, Any] = {}
        if dos_def:
            self.checks["dos_thresholds"] = DosThresholdCheck(dos_def, baseline, settings)
        if oidc_def:
            self.checks["oidc_session_reuse"] = OidcCorrelationCheck(oidc_def, settings)

        self.alert_builder = AlertBuilder(self.kb)
        self.sink = AlertSink(settings.alerts_dir)
        # Capa de trazabilidad (observacional): registra el ciclo agéntico.
        self.recorder = TraceRecorder(settings) if settings.trace_enabled else None
        # Cooldown de alertas: firma de anomalía -> epoch del último alertado.
        self._recent_alerts: dict[str, float] = {}
        self._llm: LLMClient | None = None

    @property
    def llm(self) -> LLMClient:
        """Cliente LLM perezoso (se crea al primer uso)."""
        if self._llm is None:
            self._llm = DeepSeekClient(self.settings)
        return self._llm

    # --------------------------------------------------------------- modos
    def run_oneshot(self) -> Alert:
        """Ejecuta un ciclo único de análisis y devuelve la alerta.

        Returns:
            Alert emitida (por el LLM o por fallback determinista).
        """
        logger.info("Modo oneshot: capturando estado")
        self.host_collector.self_check()
        self.events_collector.self_check()
        self._startup_diagnostics()
        context = self._build_context()
        self._prime_inputs(context)

        if not self.use_llm:
            results = self._run_all_checks(context)
            alert = self.alert_builder.from_check_results(results)
        else:
            registry = ToolRegistry(context)
            loop = ReactLoop(self.llm, registry, self.alert_builder, self.settings, self.recorder)
            alert = loop.run(self._state_summary(context))

        self._emit(alert)
        return alert

    def run_continuous(self) -> None:
        """Ejecuta el loop continuo de monitoreo.

        Mantiene una ventana deslizante de eventos y dispara el análisis ReAct
        cuando algún check determinista detecta condiciones (o en cada ciclo si
        ``always_analyze`` está activo). Se detiene con Ctrl+C.
        """
        interval = self.settings.continuous_interval_seconds
        logger.info("Modo continuous iniciado", extra={"interval_s": interval})
        # Dashboard embebido: el propio agente lo sirve, apuntando al mismo
        # alerts.jsonl que escribe (sin http.server aparte ni rutas frágiles).
        start_dashboard_server(self.settings)
        # Diagnóstico de arranque: JVM/host (para el DoS) y eventos (para OIDC).
        self.host_collector.self_check()
        self.events_collector.self_check()
        self._startup_diagnostics()
        event_window: deque = deque(maxlen=5000)

        try:
            while True:
                # Cada ciclo está aislado: un error inesperado (LLM, red, etc.)
                # se loguea y se sigue al próximo ciclo en vez de tumbar el
                # proceso. Así el monitoreo no depende del restart de Docker.
                try:
                    self._run_cycle(event_window)
                except Exception as exc:  # noqa: BLE001 - resiliencia del loop
                    logger.error(
                        "Error en ciclo de monitoreo (se continúa)",
                        extra={"error": str(exc)},
                    )
                time.sleep(interval)
        except KeyboardInterrupt:
            logger.info("Modo continuous detenido por el usuario")

    def _run_cycle(self, event_window: deque) -> None:
        """Ejecuta un ciclo de captura, checks y (si corresponde) análisis ReAct.

        Args:
            event_window: ventana deslizante de eventos compartida entre ciclos.
        """
        context = self._build_context()
        self._prime_inputs(context, event_window)
        results = self._run_all_checks(context)
        triggered = [r for r in results if r.triggered]

        if not (triggered or self.settings.always_analyze):
            return

        # Deduplicación / cooldown: evita re-analizar y re-alertar la MISMA
        # anomalía en cada ciclo mientras sigue en la ventana (ahorra tokens y
        # no inunda el dashboard). Una anomalía nueva (otra sesión, otro
        # episodio) sí dispara de inmediato.
        signature = self._trigger_signature(triggered)
        if triggered and signature and self._in_cooldown(signature):
            logger.info(
                "Anomalía ya alertada; en cooldown (se omite análisis)",
                extra={"signature": signature},
            )
            return

        logger.warning(
            "Checks dispararon, lanzando análisis ReAct",
            extra={"checks": [r.check_id for r in triggered]},
        )

        if self.use_llm:
            registry = ToolRegistry(context)
            loop = ReactLoop(self.llm, registry, self.alert_builder, self.settings, self.recorder)
            alert = loop.run(self._state_summary(context))
        else:
            alert = self.alert_builder.from_check_results(results)

        if alert.detected_cves or alert.severity != "info":
            self._emit(alert)
            # Solo se marca el cooldown ante una alerta REAL: si el análisis
            # salió degradado (info vacío), el próximo ciclo reintenta.
            if signature:
                self._mark_alerted(signature)

    # ---------------------------------------------------------- helpers
    def _trigger_signature(self, triggered: list) -> str:
        """Firma estable de las anomalías que dispararon (delegado testeable)."""
        return compute_trigger_signature(triggered)

    def _in_cooldown(self, signature: str) -> bool:
        """Indica si una firma fue alertada dentro del período de cooldown.

        Args:
            signature: firma de la anomalía.

        Returns:
            ``True`` si sigue en cooldown (no re-alertar).
        """
        cooldown = self.settings.alert_cooldown_seconds
        last = self._recent_alerts.get(signature)
        return last is not None and (time.time() - last) < cooldown

    def _mark_alerted(self, signature: str) -> None:
        """Registra que una firma acaba de generar una alerta.

        Args:
            signature: firma de la anomalía alertada.
        """
        now = time.time()
        self._recent_alerts[signature] = now
        # Poda de entradas vencidas para no crecer sin límite.
        cooldown = self.settings.alert_cooldown_seconds
        self._recent_alerts = {
            sig: ts
            for sig, ts in self._recent_alerts.items()
            if (now - ts) < cooldown
        }

    def _startup_diagnostics(self) -> None:
        """Dry-run de detección al arrancar (diagnóstico trazable).

        Busca los eventos de las últimas 24h, muestra el más reciente con su
        timestamp y ejecuta la correlación OIDC sobre ellos, informando si el
        agente detectaría el ataque. Permite validar la percepción con solo
        reiniciar el agente después de ejecutar la prueba, sin depender de
        capturar el log en el instante exacto.
        """
        try:
            wide_window = 24 * 60
            events = self.events_collector.get_recent_events(
                _OIDC_EVENT_TYPES, wide_window
            )
            if not events:
                logger.warning(
                    "Diagnóstico OIDC: 0 eventos en 24h. El agente no tiene datos "
                    "para correlacionar (revisá que la prueba genere LOGIN/"
                    "CODE_TO_TOKEN en el realm monitoreado)."
                )
                return

            newest = max(events, key=lambda e: e.time)
            logger.info(
                "Diagnóstico OIDC: eventos disponibles",
                extra={
                    "total_24h": len(events),
                    "mas_reciente_tipo": newest.type,
                    "mas_reciente_user": newest.user_id,
                    "mas_reciente_session": newest.session_id,
                    "mas_reciente_time": newest.time.isoformat(),
                },
            )

            oidc = self.checks.get("oidc_session_reuse")
            if oidc is not None:
                result = oidc.run(events=events, window_minutes=wide_window)[0]
                anomalies = result.evidence.get("anomalies", [])
                logger.info(
                    "Diagnóstico OIDC: dry-run de correlación (ventana 24h)",
                    extra={
                        "detectaria": result.triggered,
                        "anomalias": len(anomalies),
                        "detalle": anomalies[:3],
                    },
                )
        except Exception as exc:  # noqa: BLE001 - diagnóstico no debe romper nada
            logger.error("Diagnóstico de arranque falló", extra={"error": str(exc)})

    def _emit(self, alert: Alert) -> None:
        """Imprime la alerta a stdout y la persiste en el directorio de alertas.

        Args:
            alert: alerta a exponer.
        """
        _print_alert(alert)
        self.sink.write(alert)

    def _build_context(self) -> AgentContext:
        """Construye un ``AgentContext`` fresco para un ciclo."""
        return AgentContext(
            knowledge_base=self.kb,
            checks=self.checks,
            host_collector=self.host_collector,
            container_collector=self.container_collector,
            events_collector=self.events_collector,
            settings=self.settings,
        )

    def _prime_inputs(self, context: AgentContext, event_window: deque | None = None) -> None:
        """Captura señales y las deja disponibles como insumos de los checks.

        Args:
            context: contexto del ciclo.
            event_window: ventana deslizante opcional (modo continuous).
        """
        host_snapshot = self.host_collector.collect()
        fresh_events = self.events_collector.get_recent_events(
            _OIDC_EVENT_TYPES, self.settings.event_window_minutes
        )
        # Heartbeat de percepción: se loguea SIEMPRE (aunque sea 0) para dar
        # visibilidad de qué ve el agente en cada ciclo. Distingue "no hay
        # ataque" de "no me llegan eventos". Se puede acallar subiendo el nivel
        # de log o el intervalo del ciclo.
        jvm = host_snapshot.jvm
        logger.info(
            "Percepción del ciclo",
            extra={
                "eventos_en_ventana": len(fresh_events),
                "ventana_min": self.settings.event_window_minutes,
                # Señales volumétricas (DoS): visibilidad simétrica a la del OIDC.
                "cpu_percent": host_snapshot.cpu_percent,
                "total_tasks": host_snapshot.total_tasks,
                "user_threads": host_snapshot.user_threads,
                "kernel_threads": host_snapshot.kernel_threads,
                "jvm_res_mb": jvm.res_mb if jvm else None,
                "jvm_num_threads": jvm.num_threads if jvm else None,
                "jvm_cpu_percent": jvm.cpu_percent if jvm else None,
                "jvm_state": jvm.state if jvm else None,
            },
        )
        events = fresh_events
        if event_window is not None:
            for ev in fresh_events:
                event_window.append(ev)
            events = list(event_window)

        context.check_inputs["host_snapshot"] = host_snapshot
        context.check_inputs["events"] = events

    def _run_all_checks(self, context: AgentContext) -> list:
        """Ejecuta todos los checks con los insumos del contexto.

        Args:
            context: contexto con ``check_inputs`` ya poblado.

        Returns:
            Lista de ``CheckResult`` de todos los checks.
        """
        results = []
        for check in self.checks.values():
            try:
                results.extend(check.run(**context.check_inputs))
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "Check falló", extra={"check": check.check_id, "error": str(exc)}
                )
        return results

    def _state_summary(self, context: AgentContext) -> str:
        """Serializa el estado observado para el mensaje inicial del ReAct.

        Args:
            context: contexto con insumos capturados.

        Returns:
            Resumen JSON legible del estado y de los checks deterministas.
        """
        results = self._run_all_checks(context)
        host_snapshot = context.check_inputs.get("host_snapshot")
        summary = {
            "host_snapshot": host_snapshot.model_dump(mode="json") if host_snapshot else None,
            "events_count": len(context.check_inputs.get("events", [])),
            "deterministic_checks": [r.model_dump(mode="json") for r in results],
        }
        return json.dumps(summary, ensure_ascii=False, indent=2, default=str)


def _print_alert(alert: Alert) -> None:
    """Imprime la alerta como JSON estructurado por stdout.

    Args:
        alert: alerta a imprimir.
    """
    print(json.dumps(alert.model_dump(mode="json"), ensure_ascii=False, indent=2, default=str))


def _parse_args() -> argparse.Namespace:
    """Parsea los argumentos de línea de comando."""
    parser = argparse.ArgumentParser(description="Agente de análisis de seguridad Keycloak")
    parser.add_argument(
        "--mode",
        choices=["oneshot", "continuous"],
        default="continuous",
        help="Modo de operación (default: continuous).",
    )
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Opera solo con checks deterministas (sin invocar al LLM).",
    )
    return parser.parse_args()


def main() -> None:
    """Punto de entrada del proceso."""
    args = _parse_args()
    settings = get_settings()
    setup_logging(settings.log_level, settings.log_format)
    logger.info(
        "Iniciando agente",
        extra={"mode": args.mode, "realm": settings.keycloak_realm, "llm": not args.no_llm},
    )
    # Banner de features activas: si estas claves aparecen en el log, estás
    # corriendo el código con cooldown + dashboard embebido (verificación de
    # despliegue de un vistazo).
    logger.info(
        "Features activas",
        extra={
            "build": "cooldown+dashboard+dedup",
            "alert_cooldown_s": settings.alert_cooldown_seconds,
            "dashboard": (
                f"http://{settings.dashboard_host}:{settings.dashboard_port}/"
                if settings.dashboard_enabled
                else "off"
            ),
            "event_window_min": settings.event_window_minutes,
        },
    )

    agent = SecurityAgent(settings, use_llm=not args.no_llm)

    if args.mode == "oneshot":
        agent.run_oneshot()
    else:
        agent.run_continuous()


if __name__ == "__main__":
    main()
