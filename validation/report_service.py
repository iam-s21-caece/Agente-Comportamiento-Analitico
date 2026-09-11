"""Servicio de armado de reportes de validación.

Un único lugar donde se calcula el reporte (métricas por dimensión + eficiencia +
calidad) a partir de una lista de ``ScenarioResult``. Lo reutilizan tanto el CLI
(``validation_cli.py``) como el propio agente (auto-generación tras cada alerta),
respetando el principio "el cálculo vive en validación; el panel solo muestra".

La auto-generación es barata: ``evaluate_persisted`` no invoca al LLM ni a la red,
solo lee ``alerts.jsonl`` y los YAML de escenarios. Por eso el agente puede
refrescar el reporte en cada alerta sin costo de tokens.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from config.logging_config import get_logger
from config.settings import Settings, get_settings
from knowledge_base.loader import load_knowledge_base

from .campaign import evaluate_persisted
from .metrics.autonomy import compute_autonomy
from .metrics.control import compute_control
from .metrics.knowledge import compute_knowledge
from .metrics.latency import compute_latency
from .quality_rubric import aggregate
from .reporting.report_builder import CampaignReport, build_report, save_report
from .scenario_runner import ScenarioResult

logger = get_logger(__name__)

# Id estable del reporte auto-generado por el agente: se sobrescribe en cada
# refresco (un solo archivo siempre fresco), en vez de acumular timestamps.
AUTO_CAMPAIGN_ID = "campaign-latest"


def build_campaign_report(
    campaign_id: str,
    results: list[ScenarioResult],
    settings: Settings | None = None,
    mode: str = "live",
) -> CampaignReport:
    """Calcula todas las métricas y arma el ``CampaignReport``.

    Args:
        campaign_id: identificador de la campaña.
        results: resultados de los escenarios.
        settings: configuración; si se omite se usa la global.
        mode: ``"retrospectivo"`` (alertas persistidas) o ``"live"`` (ventana).

    Returns:
        El reporte consolidado, listo para persistir/renderizar.
    """
    settings = settings or get_settings()
    kb = load_knowledge_base(settings.cves_dir)
    control = compute_control(results)
    autonomy = compute_autonomy(results, kb)
    knowledge = compute_knowledge(results, kb, settings.knowledge_consistency_path)
    latency = compute_latency(results)
    quality = aggregate(settings.rubrics_dir)  # rúbrica manual (vacío si no hay)

    metadata = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "model": settings.deepseek_model,
        "realm": settings.keycloak_realm,
        "modo": mode,
    }
    if mode == "retrospectivo":
        metadata["alcance"] = (
            "Evaluación sobre alertas persistidas: solo escenarios positivos con "
            "evidencia (alertas emitidas); los no ejercidos se omiten. La tasa de "
            "falsos positivos y los negativos/ambiguos requieren corrida --live."
        )
    return build_report(
        campaign_id,
        results,
        control,
        autonomy,
        knowledge,
        metadata=metadata,
        latency=latency,
        quality=quality,
    )


def save_campaign_report(
    report: CampaignReport, settings: Settings | None = None
) -> tuple[Path, Path]:
    """Persiste el reporte (MD + JSON) en el directorio de reportes configurado.

    Args:
        report: reporte a guardar.
        settings: configuración; si se omite se usa la global.

    Returns:
        Tupla ``(ruta_markdown, ruta_json)``.
    """
    settings = settings or get_settings()
    return save_report(report, settings.validation_reports_dir)


def refresh_retrospective_report(settings: Settings | None = None) -> Path | None:
    """Regenera el reporte retrospectivo desde las alertas YA persistidas.

    Es la operación que dispara el agente (al arrancar y tras cada alerta) para que
    el dashboard exponga las métricas completas sin ningún paso manual. Sobrescribe
    un único archivo estable (``campaign-latest``).

    Args:
        settings: configuración; si se omite se usa la global.

    Returns:
        Ruta al JSON escrito, o ``None`` si aún no hay evidencia (sin alertas que
        mapeen a un escenario) — en cuyo caso no se escribe nada.
    """
    settings = settings or get_settings()
    results = evaluate_persisted(settings)
    if not results:
        return None
    report = build_campaign_report(
        AUTO_CAMPAIGN_ID, results, settings, mode="retrospectivo"
    )
    _, json_path = save_campaign_report(report, settings)
    logger.info(
        "Reporte de validación refrescado (retrospectivo)",
        extra={"scenarios": len(results), "json": str(json_path)},
    )
    return json_path
