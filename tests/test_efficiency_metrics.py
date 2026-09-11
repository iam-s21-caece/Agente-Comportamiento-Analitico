"""Tests de las métricas de eficiencia: tokens/costo (A) y tiempo de respuesta (B)."""

from __future__ import annotations

from datetime import datetime, timezone

from agent_core.llm_client import Usage, _extract_usage
from agent_core.pricing import estimate_cost_usd
from config.settings import get_settings
from validation.ground_truth import ExpectedAgentOutput, ExpectedOutput
from validation.metrics.control import compute_control
from validation.metrics.latency import compute_latency
from validation.scenario_runner import ScenarioResult, _response_times


def _result(**kwargs) -> ScenarioResult:
    """ScenarioResult mínimo para probar las métricas."""
    expected = ExpectedOutput(
        scenario_id="s",
        scenario_type="positive",
        expected_agent_output=ExpectedAgentOutput(should_alert=True),
    )
    return ScenarioResult(scenario_id="s", scenario_type="positive", expected=expected, **kwargs)


# ------------------------------------------------------------------ A: usage
class _FakeUsage:
    prompt_tokens = 100
    completion_tokens = 40
    total_tokens = 140
    prompt_cache_hit_tokens = 30
    prompt_cache_miss_tokens = 70


def test_extract_usage_reads_cache_fields() -> None:
    """El desglose de caché de DeepSeek se captura tal cual."""
    u = _extract_usage(_FakeUsage())
    assert u.total_tokens == 140
    assert u.cache_hit_tokens == 30
    assert u.cache_miss_tokens == 70


def test_extract_usage_defaults_prompt_to_miss() -> None:
    """Sin campos de caché, todo el prompt cuenta como cache-miss."""

    class NoCacheUsage:
        prompt_tokens = 50
        completion_tokens = 10
        total_tokens = 60

    u = _extract_usage(NoCacheUsage())
    assert u.cache_miss_tokens == 50
    assert u.cache_hit_tokens == 0


def test_usage_accumulates() -> None:
    """El acumulador del ReAct suma los turnos."""
    total = Usage(prompt_tokens=10, total_tokens=15) + Usage(prompt_tokens=5, total_tokens=8)
    assert total.prompt_tokens == 15
    assert total.total_tokens == 23


# ------------------------------------------------------------------ A: costo
def test_estimate_cost_matches_prices() -> None:
    """1M miss + 1M output = precio_miss + precio_output (autoconsistente)."""
    s = get_settings()
    cost = estimate_cost_usd(
        {"cache_miss_tokens": 1_000_000, "cache_hit_tokens": 0, "completion_tokens": 1_000_000}, s
    )
    expected = s.deepseek_price_input_miss_per_1m + s.deepseek_price_output_per_1m
    assert abs(cost - expected) < 1e-9


def test_control_aggregates_tokens_and_cost() -> None:
    """compute_control suma tokens y costo de la campaña (sin métrica paralela)."""
    results = [
        _result(tokens_used=1000, estimated_cost_usd=0.01, token_budget=5000),
        _result(tokens_used=500, estimated_cost_usd=0.005, token_budget=5000),
    ]
    m = compute_control(results)
    assert m.total_tokens == 1500
    assert m.estimated_cost_usd == 0.015
    assert m.budget_adherence == round(1500 / 10000, 3)


# ------------------------------------------------------------------ B: latencia
def test_response_times_from_t0() -> None:
    """El tiempo de respuesta es alerta.timestamp - t0 (inicio del ataque)."""
    t0 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    alerts = [
        {"timestamp": "2026-01-01T00:00:05Z"},
        {"timestamp": "2026-01-01T00:00:12Z"},
        {"timestamp": None},  # sin timestamp: se ignora
    ]
    assert _response_times(alerts, t0) == [5.0, 12.0]


def test_compute_latency_aggregates() -> None:
    """La latencia agrega los tiempos de todas las alertas de la campaña."""
    m = compute_latency([_result(response_times_s=[4.0, 8.0]), _result(response_times_s=[12.0])])
    assert m.count == 3
    assert m.mean_s == 8.0
    assert m.max_s == 12.0
    assert m.p50_s == 8.0


# ------------------------------------------------------------------ C: comparativa
def test_render_comparison_shows_llm_delta() -> None:
    """La comparativa expone el delta de eficacia con vs sin LLM."""
    from validation.metrics.autonomy import AutonomyMetrics
    from validation.metrics.control import ControlMetrics
    from validation.metrics.knowledge import KnowledgeMetrics
    from validation.reporting.report_builder import CampaignReport, render_comparison

    def _rep(cid: str, precision: float, cost: float) -> CampaignReport:
        return CampaignReport(
            campaign_id=cid,
            control=ControlMetrics(estimated_cost_usd=cost),
            autonomy=AutonomyMetrics(precision=precision, recall=1.0, f1=precision),
            knowledge=KnowledgeMetrics(),
        )

    out = render_comparison(_rep("llm", 1.0, 0.02), _rep("nollm", 0.4, 0.0))
    assert "aporte" in out.lower()
    assert "+0.6" in out  # delta de precisión (1.0 - 0.4)
