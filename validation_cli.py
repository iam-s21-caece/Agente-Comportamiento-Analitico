"""CLI de validación del agente.

Comandos:
    python -m validation_cli run-scenario <scenario_id>
    python -m validation_cli run-batch <scenario_type>
    python -m validation_cli run-campaign
    python -m validation_cli report <campaign_id>
    python -m validation_cli query-traces --analysis-id <id>
    python -m validation_cli evaluate-quality <alert_id>

Opciones estándar: --dry-run, --verbose, --output-format {markdown,json}.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone

from config.logging_config import get_logger, setup_logging
from config.settings import get_settings
from knowledge_base.loader import load_knowledge_base
from traceability.trace_query import get_analysis_events
from validation.campaign import alerts_from_jsonl, run_batch, run_single
from validation.metrics.autonomy import compute_autonomy
from validation.metrics.control import compute_control
from validation.metrics.knowledge import compute_knowledge
from validation.quality_rubric import (
    RUBRIC_AXES,
    blank_evaluation,
    save_evaluation,
)
from validation.reporting.report_builder import build_report, render_markdown, save_report
from validation.scenario_runner import ScenarioResult

logger = get_logger(__name__)


def _build_and_save_report(campaign_id: str, results: list[ScenarioResult]) -> None:
    """Calcula métricas, arma el reporte y lo persiste (MD + JSON)."""
    settings = get_settings()
    kb = load_knowledge_base(settings.cves_dir)
    control = compute_control(results)
    autonomy = compute_autonomy(results, kb)
    knowledge = compute_knowledge(results, kb, settings.knowledge_consistency_path)
    report = build_report(
        campaign_id,
        results,
        control,
        autonomy,
        knowledge,
        metadata={
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "model": settings.deepseek_model,
            "realm": settings.keycloak_realm,
        },
    )
    md_path, json_path = save_report(report, settings.validation_reports_dir)
    logger.info("Reporte generado", extra={"md": str(md_path), "json": str(json_path)})
    print(f"Reporte: {md_path}\n         {json_path}")


def _cmd_run_scenario(args: argparse.Namespace) -> None:
    settings = get_settings()
    provider = alerts_from_jsonl(settings.alerts_dir / "alerts.jsonl")
    if args.dry_run:
        print(f"[dry-run] ejecutaría el escenario '{args.scenario_id}'")
        return
    result = run_single(args.scenario_id, provider, settings)
    if result is None:
        return
    if args.output_format == "json":
        print(json.dumps(result.model_dump(mode="json"), ensure_ascii=False, indent=2, default=str))
    else:
        print(f"{result.scenario_id}: {'PASS' if result.passed else ('PARTIAL' if result.partial else 'FAIL')}")
        for m in result.mismatches:
            print(f"  - {m}")


def _cmd_run_batch(args: argparse.Namespace) -> None:
    settings = get_settings()
    provider = alerts_from_jsonl(settings.alerts_dir / "alerts.jsonl")
    if args.dry_run:
        print(f"[dry-run] ejecutaría el batch '{args.scenario_type}'")
        return
    results = run_batch(args.scenario_type, provider, settings)
    _build_and_save_report(f"batch-{args.scenario_type}-{_stamp()}", results)


def _cmd_run_campaign(args: argparse.Namespace) -> None:
    settings = get_settings()
    provider = alerts_from_jsonl(settings.alerts_dir / "alerts.jsonl")
    if args.dry_run:
        print("[dry-run] ejecutaría la batería completa")
        return
    results = run_batch(None, provider, settings)
    _build_and_save_report(f"campaign-{_stamp()}", results)


def _cmd_report(args: argparse.Namespace) -> None:
    settings = get_settings()
    json_path = settings.validation_reports_dir / f"{args.campaign_id}.json"
    if not json_path.exists():
        print(f"No existe el reporte {json_path}")
        return
    from validation.reporting.report_builder import CampaignReport

    report = CampaignReport.model_validate_json(json_path.read_text(encoding="utf-8"))
    if args.output_format == "json":
        print(json_path.read_text(encoding="utf-8"))
    else:
        print(render_markdown(report))


def _cmd_query_traces(args: argparse.Namespace) -> None:
    settings = get_settings()
    events = get_analysis_events(settings.traces_dir, args.analysis_id)
    for event in events:
        if args.verbose:
            print(json.dumps(event, ensure_ascii=False, default=str))
        else:
            print(f"[{event.get('seq')}] {event.get('event_type')} @ {event.get('timestamp')}")


def _cmd_evaluate_quality(args: argparse.Namespace) -> None:
    """Recolecta interactivamente la rúbrica cualitativa de una alerta."""
    settings = get_settings()
    evaluation = blank_evaluation(args.alert_id)
    print(f"Rúbrica cualitativa para {args.alert_id} (escala 0-5):\n")
    for axis, criterion in RUBRIC_AXES.items():
        print(f"— {axis}: {criterion}")
        raw = input("  score [0-5]: ").strip()
        try:
            evaluation.scores[axis] = max(0, min(5, int(raw)))
        except ValueError:
            evaluation.scores[axis] = 0
        evaluation.justification[axis] = input("  justificación: ").strip()
    path = save_evaluation(evaluation, settings.rubrics_dir)
    print(f"\nGuardado en {path} · promedio {evaluation.average}")


def _stamp() -> str:
    """Timestamp compacto para ids de campaña."""
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="validation", description="Validación del agente")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--output-format", choices=["markdown", "json"], default="markdown")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("run-scenario"); p.add_argument("scenario_id"); p.set_defaults(func=_cmd_run_scenario)
    p = sub.add_parser("run-batch"); p.add_argument("scenario_type", choices=["positive", "negative", "ambiguous"]); p.set_defaults(func=_cmd_run_batch)
    p = sub.add_parser("run-campaign"); p.set_defaults(func=_cmd_run_campaign)
    p = sub.add_parser("report"); p.add_argument("campaign_id"); p.set_defaults(func=_cmd_report)
    p = sub.add_parser("query-traces"); p.add_argument("--analysis-id", required=True); p.set_defaults(func=_cmd_query_traces)
    p = sub.add_parser("evaluate-quality"); p.add_argument("alert_id"); p.set_defaults(func=_cmd_evaluate_quality)
    return parser


def main() -> None:
    """Punto de entrada del CLI de validación."""
    settings = get_settings()
    setup_logging(settings.log_level, settings.log_format)
    args = _parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
