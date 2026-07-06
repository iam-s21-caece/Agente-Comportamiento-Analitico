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
from validation.scenario_runner import ScenarioResult


class CampaignReport(BaseModel):
    """Reporte consolidado de una campaña de validación."""

    campaign_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = Field(default_factory=dict)
    control: ControlMetrics
    autonomy: AutonomyMetrics
    knowledge: KnowledgeMetrics
    scenarios: list[dict[str, Any]] = Field(default_factory=list)


def build_report(
    campaign_id: str,
    results: list[ScenarioResult],
    control: ControlMetrics,
    autonomy: AutonomyMetrics,
    knowledge: KnowledgeMetrics,
    metadata: dict[str, Any] | None = None,
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
