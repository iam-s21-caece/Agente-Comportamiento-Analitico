"""Consolidación de resultados de una campaña en un reporte (Markdown + JSON).

El reporte deja registro auditable de una campaña de validación: configuración,
métricas por dimensión, resultado por escenario, análisis de fallos (con enlace a
las trazas) y limitaciones.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from validation.metrics.autonomy import AutonomyMetrics
from validation.metrics.control import ControlMetrics
from validation.metrics.knowledge import KnowledgeMetrics
from validation.metrics.latency import LatencyMetrics
from validation.scenario_runner import ScenarioResult


class CampaignReport(BaseModel):
    """Reporte consolidado de una campaña de validación."""

    campaign_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = Field(default_factory=dict)
    control: ControlMetrics
    autonomy: AutonomyMetrics
    knowledge: KnowledgeMetrics
    # Eficiencia (métrica nueva): tiempo de respuesta. Default para compatibilidad
    # con reportes previos que no la incluían.
    latency: LatencyMetrics = Field(default_factory=LatencyMetrics)
    # Calidad: promedio por eje de la rúbrica manual (0-5) + average_global. Vacío
    # si aún no se evaluó ninguna alerta con `evaluate-quality`.
    quality: dict[str, float] = Field(default_factory=dict)
    scenarios: list[dict[str, Any]] = Field(default_factory=list)


def build_report(
    campaign_id: str,
    results: list[ScenarioResult],
    control: ControlMetrics,
    autonomy: AutonomyMetrics,
    knowledge: KnowledgeMetrics,
    metadata: dict[str, Any] | None = None,
    latency: LatencyMetrics | None = None,
    quality: dict[str, float] | None = None,
) -> CampaignReport:
    """Construye el objeto de reporte de una campaña.

    Args:
        campaign_id: identificador de la campaña.
        results: resultados de los escenarios.
        control: métricas de control.
        autonomy: métricas de autonomía.
        knowledge: métricas de knowledge.
        metadata: metadatos (versión del agente, del modelo, fecha, etc.).

    Returns:
        CampaignReport listo para persistir/renderizar.
    """
    scenarios = [
        {
            "scenario_id": r.scenario_id,
            "scenario_type": r.scenario_type,
            "result": "pass" if r.passed else ("partial" if r.partial else "fail"),
            "detected_cves": sorted(r.detected_cves()),
            "expected_cves": sorted(r.expected.expected_cves),
            "mismatches": r.mismatches,
            "analysis_ids": r.analysis_ids,
            "tokens_used": r.tokens_used,
        }
        for r in results
    ]
    return CampaignReport(
        campaign_id=campaign_id,
        metadata=metadata or {},
        control=control,
        autonomy=autonomy,
        knowledge=knowledge,
        latency=latency or LatencyMetrics(),
        quality=quality or {},
        scenarios=scenarios,
    )


def render_markdown(report: CampaignReport) -> str:
    """Renderiza el reporte a Markdown.

    Args:
        report: reporte a renderizar.

    Returns:
        Contenido Markdown del reporte.
    """
    c, a, k = report.control, report.autonomy, report.knowledge
    lat = report.latency
    passed = sum(1 for s in report.scenarios if s["result"] == "pass")
    partial = sum(1 for s in report.scenarios if s["result"] == "partial")
    failed = sum(1 for s in report.scenarios if s["result"] == "fail")

    lines: list[str] = []
    lines.append(f"# Reporte de validación — campaña `{report.campaign_id}`")
    lines.append("")
    lines.append(f"_Generado: {report.timestamp.isoformat()}_")
    lines.append("")

    lines.append("## Resumen ejecutivo")
    lines.append(
        f"- Escenarios: **{len(report.scenarios)}** "
        f"(pass **{passed}** · partial **{partial}** · fail **{failed}**)"
    )
    lines.append(f"- Detección global: P **{a.precision}** · R **{a.recall}** · F1 **{a.f1}**")
    lines.append(f"- Crash rate: **{c.crash_rate}** · Termination: **{c.termination_rate}**")
    lines.append(
        f"- Eficiencia: **{c.total_tokens}** tokens · **${c.estimated_cost_usd}** est. · "
        f"tiempo de respuesta medio **{lat.mean_s}s**"
    )
    lines.append("")

    if report.metadata:
        lines.append("## Configuración del entorno / agente")
        for key, value in report.metadata.items():
            lines.append(f"- **{key}**: {value}")
        lines.append("")

    lines.append("## Dimensión CONTROL")
    lines.append(_kv_table(c.model_dump(exclude={"total_scenarios"})))
    lines.append("")

    lines.append("## Dimensión AUTONOMÍA")
    lines.append(_kv_table({
        "precision": a.precision,
        "recall": a.recall,
        "f1": a.f1,
        "identification_accuracy": a.identification_accuracy,
        "component_linking_accuracy": a.component_linking_accuracy,
        "reasoning_coherence_score": a.reasoning_coherence_score,
    }))
    lines.append("")

    lines.append("## Dimensión KNOWLEDGE")
    lines.append(_kv_table(k.model_dump(exclude={"detectable_cves"})))
    lines.append("")

    lines.append("## Eficiencia (tokens, costo y tiempo de respuesta)")
    lines.append(_kv_table({
        "total_tokens": c.total_tokens,
        "estimated_cost_usd": c.estimated_cost_usd,
        "budget_adherence": c.budget_adherence,
        "resp_time_mean_s": lat.mean_s,
        "resp_time_p50_s": lat.p50_s,
        "resp_time_max_s": lat.max_s,
        "resp_time_stdev_s": lat.stdev_s,
        "resp_time_muestras": lat.count,
    }))
    lines.append("")

    if report.quality:
        lines.append("## Dimensión CALIDAD (rúbrica manual 0-5)")
        lines.append(_kv_table(report.quality))
        lines.append("")

    lines.append("## Resultados por escenario")
    lines.append("| Escenario | Tipo | Resultado | Detectado | Esperado |")
    lines.append("|---|---|---|---|---|")
    for s in report.scenarios:
        lines.append(
            f"| {s['scenario_id']} | {s['scenario_type']} | {s['result']} | "
            f"{', '.join(s['detected_cves']) or '—'} | "
            f"{', '.join(s['expected_cves']) or '—'} |"
        )
    lines.append("")

    failing = [s for s in report.scenarios if s["result"] != "pass"]
    if failing:
        lines.append("## Análisis de fallos")
        for s in failing:
            lines.append(f"### {s['scenario_id']} ({s['result']})")
            for m in s["mismatches"]:
                lines.append(f"- {m}")
            if s["analysis_ids"]:
                lines.append(f"- Trazas: {', '.join(s['analysis_ids'])}")
            lines.append("")

    lines.append("## Limitaciones")
    lines.append("- Ver metadatos para versión de agente/modelo al momento de la campaña.")
    lines.append("- `reasoning_coherence_score` depende de la rúbrica humana disponible.")
    lines.append("")
    return "\n".join(lines)


def comparison_data(report_llm: CampaignReport, report_nollm: CampaignReport) -> dict[str, Any]:
    """Estructura la comparativa con vs sin LLM (para persistir/renderizar).

    Args:
        report_llm: reporte de la campaña con LLM.
        report_nollm: reporte de la campaña determinista (``--no-llm``).

    Returns:
        Dict JSON-serializable con el delta por métrica y costos/latencias.
    """
    a1, a0 = report_llm.autonomy, report_nollm.autonomy
    metrics = [
        ("precision", a0.precision, a1.precision),
        ("recall", a0.recall, a1.recall),
        ("f1", a0.f1, a1.f1),
        ("identification_accuracy", a0.identification_accuracy, a1.identification_accuracy),
        ("component_linking_accuracy", a0.component_linking_accuracy, a1.component_linking_accuracy),
    ]
    return {
        "campaign_llm": report_llm.campaign_id,
        "campaign_nollm": report_nollm.campaign_id,
        "metrics": [
            {"name": name, "nollm": v0, "llm": v1, "delta": round(v1 - v0, 3)}
            for name, v0, v1 in metrics
        ],
        "cost_llm_usd": report_llm.control.estimated_cost_usd,
        "cost_nollm_usd": report_nollm.control.estimated_cost_usd,
        "latency_llm_s": report_llm.latency.mean_s,
        "latency_nollm_s": report_nollm.latency.mean_s,
    }


def render_comparison(report_llm: CampaignReport, report_nollm: CampaignReport) -> str:
    """Compara la eficacia con y sin LLM: el aporte efectivo del modelo (objetivo 3).

    No recalcula nada: toma la dimensión de autonomía ya computada de dos campañas
    (una con el LLM activo, otra con ``--no-llm``) y expone el delta por métrica y el
    costo asociado a ese aporte.

    Args:
        report_llm: reporte de la campaña con LLM.
        report_nollm: reporte de la campaña determinista (``--no-llm``).

    Returns:
        Markdown con la tabla comparativa.
    """
    a1, a0 = report_llm.autonomy, report_nollm.autonomy
    lines: list[str] = [
        "# Comparativa determinista vs. LLM (aporte efectivo del modelo)",
        "",
        "| Métrica | sin LLM | con LLM | Δ (aporte LLM) |",
        "|---|---|---|---|",
    ]
    rows = [
        ("precision", a0.precision, a1.precision),
        ("recall", a0.recall, a1.recall),
        ("f1", a0.f1, a1.f1),
        ("identification_accuracy", a0.identification_accuracy, a1.identification_accuracy),
        ("component_linking_accuracy", a0.component_linking_accuracy, a1.component_linking_accuracy),
    ]
    for label, v0, v1 in rows:
        lines.append(f"| {label} | {v0} | {v1} | {round(v1 - v0, 3):+g} |")
    lines.append("")
    lines.append(
        f"- Costo del aporte: **${report_llm.control.estimated_cost_usd}** (con LLM) "
        f"vs **${report_nollm.control.estimated_cost_usd}** (sin LLM); "
        f"tiempo de respuesta medio **{report_llm.latency.mean_s}s** vs "
        f"**{report_nollm.latency.mean_s}s**."
    )
    lines.append("")
    return "\n".join(lines)


def save_report(report: CampaignReport, out_dir: Path | str) -> tuple[Path, Path]:
    """Persiste el reporte en Markdown y JSON.

    Args:
        report: reporte a guardar.
        out_dir: directorio destino.

    Returns:
        Tupla ``(ruta_markdown, ruta_json)``.
    """
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    md_path = directory / f"{report.campaign_id}.md"
    json_path = directory / f"{report.campaign_id}.json"
    md_path.write_text(render_markdown(report), encoding="utf-8")
    json_path.write_text(
        json.dumps(report.model_dump(mode="json"), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return md_path, json_path


def _kv_table(data: dict[str, Any]) -> str:
    """Renderiza un dict como tabla Markdown de dos columnas."""
    rows = ["| Métrica | Valor |", "|---|---|"]
    for key, value in data.items():
        rows.append(f"| {key} | {value} |")
    return "\n".join(rows)
