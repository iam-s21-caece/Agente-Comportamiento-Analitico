"""Orquestación de campañas de validación.

Ejecuta escenarios (individuales, por tipo o batería completa), recolectando las
alertas del agente desde ``alerts.jsonl`` en la ventana temporal de cada
escenario, y controla el presupuesto de tokens de la campaña.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from config.logging_config import get_logger
from config.settings import Settings, get_settings

from .ground_truth import discover_scenarios
from .scenario_runner import AlertProvider, ScenarioResult, run_scenario

logger = get_logger(__name__)


def alerts_from_jsonl(alerts_path: Path | str) -> AlertProvider:
    """Crea un ``AlertProvider`` que lee alertas de un JSONL por ventana temporal.

    Args:
        alerts_path: ruta al ``alerts.jsonl`` del agente.

    Returns:
        Callable ``(since, until) -> list[alert_dict]``.
    """
    path = Path(alerts_path)

    def provider(since: datetime, until: datetime) -> list[dict[str, Any]]:
        if not path.exists():
            logger.warning("alerts.jsonl inexistente", extra={"path": str(path)})
            return []
        selected: list[dict[str, Any]] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
                ts = datetime.fromisoformat(str(alert.get("timestamp")).replace("Z", "+00:00"))
            except (json.JSONDecodeError, ValueError):
                continue
            if since <= ts <= until:
                selected.append(alert)
        return selected

    return provider


def run_batch(
    scenario_type: str | None,
    alert_provider: AlertProvider,
    settings: Settings | None = None,
) -> list[ScenarioResult]:
    """Ejecuta todos los escenarios de un tipo (o todos si es ``None``).

    Respeta el presupuesto de tokens de la campaña: si se supera, corta con
    warning (control de costo).

    Args:
        scenario_type: ``positive`` | ``negative`` | ``ambiguous`` o ``None``.
        alert_provider: proveedor de alertas por ventana temporal.
        settings: configuración opcional.

    Returns:
        Lista de ``ScenarioResult``.
    """
    settings = settings or get_settings()
    scenario_dirs = discover_scenarios(settings.scenarios_dir, scenario_type)
    budget = settings.validation_token_budget

    results: list[ScenarioResult] = []
    spent = 0
    for scenario_dir in scenario_dirs:
        if spent >= budget:
            logger.warning(
                "Presupuesto de tokens agotado; se detiene la campaña",
                extra={"spent": spent, "budget": budget},
            )
            break
        result = run_scenario(scenario_dir, alert_provider, token_budget=budget)
        spent += result.tokens_used
        results.append(result)
        logger.info(
            "Escenario ejecutado",
            extra={"scenario_id": result.scenario_id, "result": _label(result)},
        )
    return results


def run_single(
    scenario_id: str,
    alert_provider: AlertProvider,
    settings: Settings | None = None,
) -> ScenarioResult | None:
    """Ejecuta un único escenario por id.

    Args:
        scenario_id: id del escenario a ejecutar.
        alert_provider: proveedor de alertas.
        settings: configuración opcional.

    Returns:
        El ``ScenarioResult``, o ``None`` si no se encontró el escenario.
    """
    settings = settings or get_settings()
    for scenario_dir in discover_scenarios(settings.scenarios_dir):
        if scenario_dir.name == scenario_id:
            return run_scenario(scenario_dir, alert_provider, token_budget=settings.validation_token_budget)
    logger.error("Escenario no encontrado", extra={"scenario_id": scenario_id})
    return None


def _label(result: ScenarioResult) -> str:
    """Etiqueta legible del resultado (pass/partial/fail)."""
    return "pass" if result.passed else ("partial" if result.partial else "fail")
