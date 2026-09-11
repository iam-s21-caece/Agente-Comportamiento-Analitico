"""Tools invocables por el LLM dentro del bucle ReAct.

Cada tool expone una capacidad del agente (capturar métricas, leer eventos,
correr un check, consultar conocimiento, emitir la alerta). El ``ToolRegistry``
provee tanto las especificaciones JSON-schema (para el tool calling) como el
despacho a la implementación Python.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Callable

from config.logging_config import get_logger
from config.settings import Settings, get_settings
from deterministic_checks.base import CheckBase
from knowledge_base.loader import KnowledgeBase
from signal_collector.connection_collector import ConnectionCollector
from signal_collector.container_metrics import ContainerMetricsCollector
from signal_collector.host_metrics import HostMetricsCollector
from signal_collector.keycloak_events import KeycloakEventsCollector

logger = get_logger(__name__)


class AgentContext:
    """Contenedor de dependencias compartidas por las tools.

    Mantiene los colectores, los checks indexados por id, la base de conocimiento
    y un "sink" donde se deposita la alerta final que emite el LLM.
    """

    def __init__(
        self,
        knowledge_base: KnowledgeBase,
        checks: dict[str, CheckBase],
        host_collector: HostMetricsCollector,
        container_collector: ContainerMetricsCollector,
        events_collector: KeycloakEventsCollector,
        settings: Settings | None = None,
        connection_collector: ConnectionCollector | None = None,
    ) -> None:
        """Inicializa el contexto.

        Args:
            knowledge_base: definiciones de CVEs.
            checks: checks deterministas indexados por ``check_id``.
            host_collector: colector de métricas de host/JVM.
            container_collector: colector de métricas de contenedor.
            events_collector: colector de eventos de Keycloak.
            settings: configuración opcional.
            connection_collector: colector de conexiones por IP (atribución DoS);
                si se omite se crea uno con la configuración vigente.
        """
        self.kb = knowledge_base
        self.checks = checks
        self.host_collector = host_collector
        self.container_collector = container_collector
        self.events_collector = events_collector
        self.settings = settings or get_settings()
        self.connection_collector = connection_collector or ConnectionCollector(self.settings)
        # Insumos de check que dependen de datos frescos (eventos, snapshots).
        self.check_inputs: dict[str, Any] = {}
        # Alerta emitida por el LLM vía emit_alert (None hasta que se emite).
        self.emitted_alert: dict[str, Any] | None = None


class ToolRegistry:
    """Registro de tools: specs JSON-schema + despacho a Python."""

    def __init__(self, context: AgentContext) -> None:
        """Inicializa el registro.

        Args:
            context: contexto con las dependencias del agente.
        """
        self.ctx = context
        self._handlers: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
            "get_host_metrics_snapshot": self._get_host_metrics,
            "get_container_metrics_snapshot": self._get_container_metrics,
            "get_keycloak_events": self._get_keycloak_events,
            "get_connection_snapshot": self._get_connection_snapshot,
            "run_deterministic_check": self._run_check,
            "get_cve_knowledge": self._get_cve_knowledge,
            "emit_alert": self._emit_alert,
        }

    # ------------------------------------------------------------- dispatch
    def dispatch(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Ejecuta una tool por nombre.

        Args:
            name: nombre de la tool.
            arguments: argumentos provistos por el LLM.

        Returns:
            Resultado JSON-serializable de la tool. Errores se devuelven como
            ``{"error": ...}`` para que el LLM pueda reaccionar.
        """
        handler = self._handlers.get(name)
        if handler is None:
            return {"error": f"Tool desconocida: {name}"}
        try:
            return handler(arguments or {})
        except Exception as exc:  # noqa: BLE001 - nunca crashear el loop
            logger.error("Error ejecutando tool", extra={"tool": name, "error": str(exc)})
            return {"error": str(exc)}

    @property
    def is_alert_emitted(self) -> bool:
        """``True`` si ya se emitió la alerta final."""
        return self.ctx.emitted_alert is not None

    # ------------------------------------------------------------- handlers
    def _get_host_metrics(self, _: dict[str, Any]) -> dict[str, Any]:
        """Devuelve un snapshot fresco de métricas de host/JVM."""
        snap = self.ctx.host_collector.collect()
        self.ctx.check_inputs["host_snapshot"] = snap
        return snap.model_dump(mode="json")

    def _get_container_metrics(self, _: dict[str, Any]) -> dict[str, Any]:
        """Devuelve un snapshot fresco de métricas del contenedor."""
        return self.ctx.container_collector.collect().model_dump(mode="json")

    def _get_keycloak_events(self, args: dict[str, Any]) -> dict[str, Any]:
        """Devuelve eventos de Keycloak filtrados.

        Args:
            args: puede incluir ``event_types`` (list[str]), ``since`` y
                ``until`` (ISO-8601) o ``window_minutes``.
        """
        event_types = args.get("event_types")
        since = _parse_iso(args.get("since"))
        until = _parse_iso(args.get("until"))
        if since or until:
            events = self.ctx.events_collector.get_events(
                event_types=event_types, since=since, until=until
            )
        else:
            window = int(args.get("window_minutes", self.ctx.settings.event_window_minutes))
            events = self.ctx.events_collector.get_recent_events(event_types, window)
        self.ctx.check_inputs["events"] = events
        return {
            "count": len(events),
            "events": [e.model_dump(mode="json") for e in events],
        }

    def _get_connection_snapshot(self, _: dict[str, Any]) -> dict[str, Any]:
        """Devuelve las conexiones activas hacia Keycloak, agregadas por IP.

        Para el DoS (CVE-2026-33871): identifica el/los origen(es) con concurrencia
        anómala. Marca ``masked`` si la IP top es loopback/privada (enmascarada por
        NAT/proxy/túnel), en cuyo caso la concurrencia es real pero la IP no es la
        del atacante externo.
        """
        return self.ctx.connection_collector.collect().model_dump(mode="json")

    def _run_check(self, args: dict[str, Any]) -> dict[str, Any]:
        """Ejecuta un check determinista por id.

        Args:
            args: debe incluir ``check_id``.
        """
        check_id = args.get("check_id", "")
        check = self.ctx.checks.get(check_id)
        if check is None:
            return {"error": f"Check inexistente: {check_id}. Disponibles: "
                    f"{list(self.ctx.checks)}"}
        results = check.run(**self.ctx.check_inputs)
        return {"results": [r.model_dump(mode="json") for r in results]}

    def _get_cve_knowledge(self, args: dict[str, Any]) -> dict[str, Any]:
        """Devuelve la definición estructurada de una CVE.

        Args:
            args: debe incluir ``cve_id``.
        """
        cve_id = args.get("cve_id", "")
        definition = self.ctx.kb.get(cve_id)
        if definition is None:
            return {"error": f"CVE no encontrada: {cve_id}"}
        return definition.model_dump(mode="json")

    def _emit_alert(self, args: dict[str, Any]) -> dict[str, Any]:
        """Recibe la alerta final del LLM y la deposita en el contexto.

        Args:
            args: dict de la alerta según el esquema del prompt.
        """
        self.ctx.emitted_alert = args
        logger.info("Alerta emitida por el LLM", extra={"severity": args.get("severity")})
        return {"status": "alert_received"}

    # --------------------------------------------------------------- specs
    @staticmethod
    def get_specs() -> list[dict[str, Any]]:
        """Devuelve las especificaciones JSON-schema de todas las tools.

        Returns:
            Lista de tools en formato OpenAI tool-calling.
        """
        return [
            _spec(
                "get_host_metrics_snapshot",
                "Captura métricas actuales del host y del proceso JVM de Keycloak "
                "(CPU, threads usuario/kernel, tasks, VIRT/RES/SHR, estado).",
                {},
            ),
            _spec(
                "get_container_metrics_snapshot",
                "Captura métricas actuales del contenedor de Keycloak "
                "(CPU%, memoria, PIDs).",
                {},
            ),
            _spec(
                "get_keycloak_events",
                "Obtiene eventos de autenticación de Keycloak (LOGIN, CODE_TO_TOKEN, "
                "etc.) vía Admin REST API, filtrando por tipo y rango temporal.",
                {
                    "event_types": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Tipos de evento a filtrar.",
                    },
                    "since": {"type": "string", "description": "ISO-8601 inicio."},
                    "until": {"type": "string", "description": "ISO-8601 fin."},
                    "window_minutes": {
                        "type": "integer",
                        "description": "Alternativa: últimos N minutos.",
                    },
                },
            ),
            _spec(
                "get_connection_snapshot",
                "Enumera las conexiones TCP activas hacia el puerto de Keycloak, "
                "agregadas por IP de origen (top-talkers). Sirve para ATRIBUIR el "
                "origen de un flood (CVE-2026-33871): la IP con concurrencia anómala. "
                "Si 'masked' es true, la IP top es loopback/privada (enmascarada por "
                "NAT/proxy/túnel): reportá la concurrencia pero aclarando la máscara.",
                {},
            ),
            _spec(
                "run_deterministic_check",
                "Ejecuta un check determinista por id y devuelve su CheckResult. "
                "Ids: 'dos_thresholds' (CVE-2026-33871), 'oidc_session_reuse' "
                "(CVE-2023-0264).",
                {
                    "check_id": {
                        "type": "string",
                        "enum": ["dos_thresholds", "oidc_session_reuse"],
                    }
                },
                required=["check_id"],
            ),
            _spec(
                "get_cve_knowledge",
                "Devuelve la definición estructurada (YAML) de una CVE conocida.",
                {"cve_id": {"type": "string"}},
                required=["cve_id"],
            ),
            _spec(
                "emit_alert",
                "Emite la alerta estructurada final y termina el análisis.",
                {
                    "severity": {
                        "type": "string",
                        "enum": ["info", "low", "medium", "high", "critical"],
                    },
                    "chained": {"type": "boolean"},
                    "summary": {"type": "string"},
                    "detected_cves": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": "Lista de CVEs detectadas (ver esquema del prompt).",
                    },
                },
                required=["severity", "summary", "detected_cves"],
            ),
        ]


def _spec(
    name: str,
    description: str,
    properties: dict[str, Any],
    required: list[str] | None = None,
) -> dict[str, Any]:
    """Construye una spec de tool en formato OpenAI tool-calling.

    Args:
        name: nombre de la tool.
        description: descripción para el LLM.
        properties: propiedades del schema de parámetros.
        required: parámetros obligatorios.

    Returns:
        Dict con la especificación de la tool.
    """
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required or [],
            },
        },
    }


def _parse_iso(value: str | None) -> datetime | None:
    """Parsea una fecha ISO-8601 de forma tolerante.

    Args:
        value: cadena ISO-8601 o ``None``.

    Returns:
        ``datetime`` o ``None`` si no se pudo parsear.
    """
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
