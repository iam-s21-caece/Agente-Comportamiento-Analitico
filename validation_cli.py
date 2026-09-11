"""CLI de validación del agente.

Comandos:
    python -m validation_cli run-campaign            # retrospectivo (default)
    python -m validation_cli run-campaign --live     # espera la ventana; disparás
    python -m validation_cli run-scenario <scenario_id>
    python -m validation_cli run-batch <scenario_type>
    python -m validation_cli report <campaign_id>
    python -m validation_cli compare <camp_llm> <camp_nollm> [--save]
    python -m validation_cli query-traces --analysis-id <id>
    python -m validation_cli evaluate-quality <alert_id>

``run-campaign`` (sin ``--live``) evalúa las alertas que el agente YA emitió contra
el ground truth, sin esperar ni disparar ataques: llena el panel de resultados al
instante y sin gastar tokens. ``--live`` corre la campaña observando la ventana de
cada escenario (rigurosa, requiere disparar los ataques a mano).

Opciones estándar: --dry-run, --verbose, --output-format {markdown,json}.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone

from config.logging_config import get_logger, setup_logging
from config.settings import get_settings
from traceability.trace_query import get_analysis_events
from validation.campaign import (
    alerts_from_jsonl,
    analyses_from_traces,
    evaluate_persisted,
    run_batch,
    run_single,
)
from validation.quality_rubric import (
    RUBRIC_AXES,
    blank_evaluation,
    save_evaluation,
)
from validation.report_service import build_campaign_report, save_campaign_report
from validation.reporting.report_builder import render_markdown
from validation.scenario_runner import ScenarioResult

logger = get_logger(__name__)


def _build_and_save_report(
    campaign_id: str, results: list[ScenarioResult], mode: str = "live"
) -> None:
    """Calcula métricas, arma el reporte y lo persiste (MD + JSON).

    Args:
        campaign_id: identificador de la campaña.
        results: resultados de los escenarios.
        mode: ``"retrospectivo"`` (alertas persistidas) o ``"live"`` (ventana
            observada). Se registra en los metadatos para dejar auditable qué se
            evaluó (p. ej. que el modo retrospectivo no cubre negativos/FP).
    """
    settings = get_settings()
    report = build_campaign_report(campaign_id, results, settings, mode=mode)
    md_path, json_path = save_campaign_report(report, settings)
    logger.info("Reporte generado", extra={"md": str(md_path), "json": str(json_path)})
    print(f"Reporte: {md_path}\n         {json_path}")


def _cmd_run_scenario(args: argparse.Namespace) -> None:
    settings = get_settings()
    provider = alerts_from_jsonl(settings.alerts_dir / "alerts.jsonl")
    if args.dry_run:
        print(f"[dry-run] ejecutaría el escenario '{args.scenario_id}'")
        return
    traces = analyses_from_traces(settings.traces_dir, settings)
    result = run_single(args.scenario_id, provider, settings, trace_provider=traces)
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
    traces = analyses_from_traces(settings.traces_dir, settings)
    results = run_batch(args.scenario_type, provider, settings, trace_provider=traces)
    _build_and_save_report(f"batch-{args.scenario_type}-{_stamp()}", results)


def _cmd_run_campaign(args: argparse.Namespace) -> None:
    settings = get_settings()
    if args.dry_run:
        print("[dry-run] ejecutaría la batería completa")
        return
    if getattr(args, "live", False):
        # Corrida en vivo: espera la ventana de cada escenario (disparás el ataque
        # manualmente durante ese lapso). Rigurosa pero requiere babysitting.
        provider = alerts_from_jsonl(settings.alerts_dir / "alerts.jsonl")
        traces = analyses_from_traces(settings.traces_dir, settings)
        results = run_batch(None, provider, settings, trace_provider=traces)
        _build_and_save_report(f"campaign-{_stamp()}", results, mode="live")
    else:
        # Retrospectivo (default): evalúa las alertas que el agente YA emitió, sin
        # esperar ni disparar nada. Llena el panel de resultados al instante.
        results = evaluate_persisted(settings)
        _build_and_save_report(f"campaign-{_stamp()}", results, mode="retrospectivo")


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


def _cmd_compare(args: argparse.Namespace) -> None:
    """Compara dos campañas (con LLM vs --no-llm) y expone el aporte del LLM."""
    settings = get_settings()
    from validation.reporting.report_builder import CampaignReport, render_comparison

    def _load(campaign_id: str) -> "CampaignReport | None":
        path = settings.validation_reports_dir / f"{campaign_id}.json"
        if not path.exists():
            print(f"No existe el reporte {path}")
            return None
        return CampaignReport.model_validate_json(path.read_text(encoding="utf-8"))

    report_llm = _load(args.campaign_llm)
    report_nollm = _load(args.campaign_nollm)
    if report_llm and report_nollm:
        print(render_comparison(report_llm, report_nollm))
        if getattr(args, "save", False):
            from validation.reporting.report_builder import comparison_data

            out = settings.validation_reports_dir / "comparison.json"
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(
                json.dumps(comparison_data(report_llm, report_nollm), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            print(f"Comparativa guardada en {out} (visible en el dashboard).")


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
    p = sub.add_parser("run-campaign"); p.add_argument("--live", action="store_true", help="Corrida en vivo: espera la ventana de cada escenario (disparás el ataque). Por defecto es retrospectiva sobre alertas persistidas."); p.set_defaults(func=_cmd_run_campaign)
    p = sub.add_parser("report"); p.add_argument("campaign_id"); p.set_defaults(func=_cmd_report)
    p = sub.add_parser("compare"); p.add_argument("campaign_llm"); p.add_argument("campaign_nollm"); p.add_argument("--save", action="store_true", help="Persiste comparison.json para el dashboard"); p.set_defaults(func=_cmd_compare)
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
