"""Test del bucle ReAct con un cliente LLM falso (sin red)."""

from __future__ import annotations

from pathlib import Path

from agent_core.llm_client import LLMClient, LLMResponse, ToolCall
from agent_core.react_loop import ReactLoop
from agent_core.tools import AgentContext, ToolRegistry
from alert_builder.builder import AlertBuilder
from knowledge_base.loader import load_knowledge_base

CVES_DIR = Path(__file__).parent.parent / "knowledge_base" / "cves"


class ScriptedLLM(LLMClient):
    """Cliente LLM que reproduce una secuencia fija de respuestas."""

    def __init__(self, responses: list[LLMResponse]) -> None:
        self._responses = responses
        self._i = 0

    def chat(self, messages, tools=None) -> LLMResponse:  # noqa: D401, ANN001
        """Devuelve la siguiente respuesta del guion."""
        response = self._responses[min(self._i, len(self._responses) - 1)]
        self._i += 1
        return response


def _context() -> AgentContext:
    """Construye un contexto mínimo con colectores no usados por el test."""
    kb = load_knowledge_base(CVES_DIR)
    return AgentContext(
        knowledge_base=kb,
        checks={},
        host_collector=None,  # type: ignore[arg-type]
        container_collector=None,  # type: ignore[arg-type]
        events_collector=None,  # type: ignore[arg-type]
    )


def test_react_loop_emits_validated_alert() -> None:
    """El loop debe terminar y validar la alerta cuando el LLM llama emit_alert."""
    payload = {
        "severity": "critical",
        "chained": False,
        "summary": "Account takeover detectado por reuse de session_id.",
        "detected_cves": [
            {
                "cve_id": "CVE-2023-0264",
                "confidence": 0.95,
                "affected_component": {
                    "layer": "application",
                    "stack": ["keycloak", "oidc"],
                    "specific_module": "CODE_TO_TOKEN",
                },
                "evidence": [
                    {
                        "source": "oidc_session_reuse",
                        "kind": "correlational",
                        "description": "session-X reutilizada por mallory",
                        "data": {},
                    }
                ],
                "narrative": "mallory reutilizó el session_id de alice en CODE_TO_TOKEN.",
            }
        ],
    }
    responses = [
        LLMResponse(
            content="Razonando: pido la alerta final.",
            tool_calls=[ToolCall(id="call-1", name="emit_alert", arguments=payload)],
        )
    ]

    context = _context()
    registry = ToolRegistry(context)
    builder = AlertBuilder(context.kb)
    loop = ReactLoop(ScriptedLLM(responses), registry, builder)

    alert = loop.run("estado de prueba")

    assert alert.severity == "critical"
    assert len(alert.detected_cves) == 1
    assert alert.detected_cves[0].cve_id == "CVE-2023-0264"
    assert alert.detected_cves[0].affected_component.layer == "application"


def test_react_loop_falls_back_without_alert() -> None:
    """Si el LLM nunca emite alerta, el loop cae al fallback determinista."""
    responses = [LLMResponse(content="No hago nada útil.")]

    context = _context()
    registry = ToolRegistry(context)
    builder = AlertBuilder(context.kb)
    loop = ReactLoop(ScriptedLLM(responses), registry, builder)

    alert = loop.run("estado de prueba")

    # Sin checks ni detecciones, el fallback produce una alerta info vacía.
    assert alert.severity == "info"
    assert alert.detected_cves == []
