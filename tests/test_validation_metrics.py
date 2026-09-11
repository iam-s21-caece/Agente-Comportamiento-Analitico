"""Tests de las métricas de validación (control, autonomía, knowledge)."""

from __future__ import annotations

from pathlib import Path

from knowledge_base.loader import load_knowledge_base
from validation.ground_truth import ExpectedAgentOutput, ExpectedOutput
from validation.metrics.autonomy import compute_autonomy
from validation.metrics.control import compute_control
from validation.metrics.knowledge import compute_knowledge
from validation.scenario_runner import ScenarioResult

CVES_DIR = Path(__file__).parent.parent / "knowledge_base" / "cves"
CONSISTENCY = Path(__file__).parent.parent / "validation" / "knowledge_consistency.yaml"


def _expected(scenario_id, stype, cves, layers, should_alert=True) -> ExpectedOutput:
    """Construye un ExpectedOutput sintético."""
    return ExpectedOutput(
        scenario_id=scenario_id,
        scenario_type=stype,
        expected_agent_output=ExpectedAgentOutput(
            should_alert=should_alert,
            should_identify_cves=cves,
            should_link_component=layers,
            expected_confidence_range=[0.6, 1.0],
        ),
    )


def _result(scenario_id, stype, expected, alerts, **control) -> ScenarioResult:
    """Construye un ScenarioResult sintético."""
    return ScenarioResult(
        scenario_id=scenario_id,
        scenario_type=stype,
        expected=expected,
        alerts=alerts,
        **control,
    )


def _alert(cve_id, conf, layer) -> dict:
    return {
        "severity": "high",
        "detected_cves": [
            {"cve_id": cve_id, "confidence": conf, "affected_component": {"layer": layer}}
        ],
    }


def _campaign() -> list[ScenarioResult]:
    """Campaña sintética: 2 positivos correctos + 1 negativo silencioso."""
    oidc = _expected("p-oidc", "positive", ["CVE-2023-0264"], ["application"])
    dos = _expected("p-dos", "positive", ["CVE-2026-33871"], ["infrastructure"])
    neg = _expected("n-normal", "negative", [], [], should_alert=False)
    return [
        _result("p-oidc", "positive", oidc, [_alert("CVE-2023-0264", 0.9, "application")]),
        _result("p-dos", "positive", dos, [_alert("CVE-2026-33871", 0.8, "infrastructure")]),
        _result("n-normal", "negative", neg, []),
    ]


def test_control_metrics_all_terminated() -> None:
    """Sin crashes ni timeouts, termination_rate = 1 y crash_rate = 0."""
    metrics = compute_control(_campaign())
    assert metrics.termination_rate == 1.0
    assert metrics.crash_rate == 0.0
    assert metrics.total_scenarios == 3


def test_control_metrics_counts_crash() -> None:
    """Un crash se refleja en crash_rate."""
    results = _campaign()
    results[0].crashed = True
    results[0].terminated_ok = False
    metrics = compute_control(results)
    assert metrics.crash_rate == round(1 / 3, 3)
    assert metrics.termination_rate == round(2 / 3, 3)


def test_autonomy_perfect_detection() -> None:
    """Detección perfecta: precision = recall = f1 = 1."""
    kb = load_knowledge_base(CVES_DIR)
    metrics = compute_autonomy(_campaign(), kb)
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert metrics.f1 == 1.0
    assert metrics.identification_accuracy == 1.0
    assert metrics.component_linking_accuracy == 1.0


def test_autonomy_penalizes_false_positive() -> None:
    """Un FP (CVE detectada no esperada) baja la precisión."""
    kb = load_knowledge_base(CVES_DIR)
    results = _campaign()
    # El negativo ahora alerta erróneamente una CVE conocida.
    results[2].alerts = [_alert("CVE-2026-33871", 0.9, "infrastructure")]
    metrics = compute_autonomy(results, kb)
    assert metrics.global_counts.fp == 1
    assert metrics.precision < 1.0


def test_knowledge_coverage_and_consistency() -> None:
    """Cobertura total (ambas CVEs detectadas) y consistencia desde el registro."""
    kb = load_knowledge_base(CVES_DIR)
    metrics = compute_knowledge(_campaign(), kb, CONSISTENCY)
    assert metrics.coverage == 1.0
    assert set(metrics.detectable_cves) == {"CVE-2023-0264", "CVE-2026-33871"}
    assert metrics.knowledge_consistency_score == 1.0
