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

from agent_core.pricing import estimate_cost_usd
from config.logging_config import get_logger
from config.settings import Settings, get_settings
from traceability.trace_query import iter_events

from .ground_truth import discover_scenarios, load_expected, load_scenario_spec
from .scenario_runner import (
    AlertProvider,
    ScenarioResult,
    TraceProvider,
    compare,
    run_scenario,
)

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


def read_all_alerts(alerts_path: Path | str) -> list[dict[str, Any]]:
    """Lee TODAS las alertas persistidas (sin ventana temporal).

    Es el insumo del modo retrospectivo: en vez de esperar una ventana futura,
    evalúa lo que el agente ya emitió.

    Args:
        alerts_path: ruta al ``alerts.jsonl`` del agente.

    Returns:
        Lista de alertas (dicts), en orden de aparición.
    """
    path = Path(alerts_path)
    if not path.exists():
        logger.warning("alerts.jsonl inexistente", extra={"path": str(path)})
        return []
    alerts: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            alerts.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return alerts


def _detected_set(alert: dict[str, Any]) -> set[str]:
    """CVE-IDs detectados en una alerta (en mayúsculas)."""
    return {
        (c.get("cve_id") or "").upper()
        for c in alert.get("detected_cves", [])
        if c.get("cve_id")
    }


def _best_scenario(detected: set[str], specs: list[tuple[str, set[str]]]) -> str | None:
    """Asigna una alerta al escenario positivo que mejor explica sus CVEs.

    Prioriza (1) coincidencia exacta, (2) mayor intersección, (3) escenario más
    específico (menos CVEs esperadas). Garantiza asignación ÚNICA de cada alerta a
    lo sumo un escenario, evitando el doble conteo de tokens/costo en el agregado.

    Args:
        detected: CVEs detectadas por la alerta.
        specs: pares ``(scenario_id, expected_cves)`` de los escenarios candidatos.

    Returns:
        El ``scenario_id`` elegido, o ``None`` si la alerta no explica ninguno.
    """
    best_id: str | None = None
    best_key: tuple[int, int, int] = (-1, -1, 1)
    for sid, expected in specs:
        inter = len(detected & expected)
        if inter == 0:
            continue
        key = (1 if detected == expected else 0, inter, -len(expected))
        if key > best_key:
            best_key = key
            best_id = sid
    return best_id


def _alert_metric(alert: dict[str, Any], key: str) -> Any:
    """Lee ``alert.metrics[key]`` de forma tolerante (métricas pueden faltar)."""
    metrics = alert.get("metrics") or {}
    return metrics.get(key)


def evaluate_persisted(settings: Settings | None = None) -> list[ScenarioResult]:
    """Evalúa retrospectivamente las alertas YA persistidas contra el ground truth.

    No espera ni dispara ataques: toma las alertas reales que el agente emitió, las
    asigna al escenario positivo que explica sus CVEs y arma los ``ScenarioResult``
    reutilizando ``compare`` y las métricas existentes. Las métricas de eficiencia
    (tokens, costo, tiempo de respuesta) se leen de ``alert.metrics`` —lo que el
    agente ya midió—, de modo que el reporte coincide con el panel de parámetros en
    vivo del dashboard.

    Limitación (documentada en el reporte): los escenarios negativos/ambiguos no son
    evaluables retrospectivamente (``alerts.jsonl`` solo tiene líneas cuando el
    agente alertó; no hay ventanas benignas registradas). La tasa de falsos
    positivos y esos escenarios requieren una campaña controlada (``--live``).

    Args:
        settings: configuración; si se omite se usa la global.

    Returns:
        Lista de ``ScenarioResult`` (uno por escenario positivo), evaluados.
    """
    settings = settings or get_settings()
    alerts = read_all_alerts(settings.alerts_dir / "alerts.jsonl")
    scenario_dirs = discover_scenarios(settings.scenarios_dir, "positive")

    specs = [
        (
            load_scenario_spec(d / "scenario.yaml"),
            load_expected(d / "expected.yaml"),
        )
        for d in scenario_dirs
    ]
    id_expected = [(spec.scenario_id, exp.expected_cves) for spec, exp in specs]

    # Asignación única de cada alerta al escenario que mejor la explica.
    buckets: dict[str, list[dict[str, Any]]] = {spec.scenario_id: [] for spec, _ in specs}
    for alert in alerts:
        detected = _detected_set(alert)
        if not detected:
            continue
        sid = _best_scenario(detected, id_expected)
        if sid is not None:
            buckets[sid].append(alert)

    budget = settings.validation_token_budget
    results: list[ScenarioResult] = []
    omitted: list[str] = []
    for spec, expected in specs:
        matched = buckets[spec.scenario_id]
        # Sin evidencia (ninguna alerta asignada) el escenario no fue ejercido en
        # esta corrida: se OMITE en vez de contarlo como fallo. Retrospectivamente
        # no se puede distinguir "no ejecutado" de "ejecutado y no detectado";
        # afirmar un fallo sería aseverar algo no verificable.
        if not matched:
            omitted.append(spec.scenario_id)
            continue
        result = ScenarioResult(
            scenario_id=spec.scenario_id,
            scenario_type=spec.scenario_type,
            expected=expected,
            token_budget=budget,
            alerts=matched,
        )
        # Eficiencia: leída de lo que el agente ya estampó en cada alerta.
        result.tokens_used = sum(int(_alert_metric(a, "tokens") or 0) for a in matched)
        result.estimated_cost_usd = round(
            sum(float(_alert_metric(a, "cost_usd") or 0.0) for a in matched), 6
        )
        result.response_times_s = [
            float(_alert_metric(a, "response_time_s"))
            for a in matched
            if _alert_metric(a, "response_time_s") is not None
        ]
        # Trazabilidad: cada alerta es su propio anclaje (alert_id).
        result.analysis_ids = [a["alert_id"] for a in matched if a.get("alert_id")]
        results.append(compare(expected, result))
    if omitted:
        logger.info(
            "Escenarios omitidos por falta de evidencia (retrospectivo)",
            extra={"scenarios": omitted},
        )
    return results


def analyses_from_traces(
    traces_dir: Path | str, settings: Settings | None = None
) -> TraceProvider:
    """Crea un ``TraceProvider`` que resume tokens/costo por análisis desde la traza.

    Lee los eventos ``analysis_end`` (que llevan el consumo de tokens grabado por el
    agente) dentro de la ventana temporal, y estima el costo con los precios de la
    configuración. Es el nexo entre el runtime del agente y las métricas de eficiencia,
    sin acoplar la validación a la ejecución en vivo.

    Args:
        traces_dir: directorio raíz de trazas del agente.
        settings: configuración con los precios de DeepSeek.

    Returns:
        Callable ``(since, until) -> list[{analysis_id, total_tokens, cost_usd}]``.
    """
    root = Path(traces_dir)
    cfg = settings or get_settings()

    def provider(since: datetime, until: datetime) -> list[dict[str, Any]]:
        summaries: list[dict[str, Any]] = []
        for event in iter_events(root, event_type="analysis_end", since=since, until=until):
            payload = event.get("payload", {}) or {}
            tokens = payload.get("tokens", {}) or {}
            summaries.append(
                {
                    "analysis_id": event.get("analysis_id"),
                    "total_tokens": int(tokens.get("total_tokens", 0) or 0),
                    "cost_usd": estimate_cost_usd(tokens, cfg),
                }
            )
        return summaries

    return provider


def run_batch(
    scenario_type: str | None,
    alert_provider: AlertProvider,
    settings: Settings | None = None,
    trace_provider: TraceProvider | None = None,
    observe_window: bool = True,
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
        result = run_scenario(
            scenario_dir,
            alert_provider,
            token_budget=budget,
            trace_provider=trace_provider,
            observe_window=observe_window,
        )
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
    trace_provider: TraceProvider | None = None,
    observe_window: bool = True,
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
            return run_scenario(
                scenario_dir,
                alert_provider,
                token_budget=settings.validation_token_budget,
                trace_provider=trace_provider,
                observe_window=observe_window,
            )
    logger.error("Escenario no encontrado", extra={"scenario_id": scenario_id})
    return None


def _label(result: ScenarioResult) -> str:
    """Etiqueta legible del resultado (pass/partial/fail)."""
    return "pass" if result.passed else ("partial" if result.partial else "fail")
