"""Tests del modo retrospectivo: evaluar alertas persistidas sin esperar ventanas.

Verifica la asignación única de alertas a escenarios (sin doble conteo) y que las
métricas de eficiencia se lean de ``alert.metrics`` (lo que el agente ya estampó),
de modo que el reporte coincida con el panel en vivo.
"""

from __future__ import annotations

import json
from pathlib import Path

from config.settings import get_settings
from validation.campaign import _best_scenario, evaluate_persisted

ROOT = Path(__file__).resolve().parent.parent
SCENARIOS = ROOT / "validation" / "scenarios"


def _alert(cve_ids: list[str], *, tokens: int, cost: float, rt: float, conf: float = 0.9) -> dict:
    """Alerta persistida mínima con las métricas que estampa el agente."""
    return {
        "alert_id": f"alert-{'-'.join(cve_ids).lower()}",
        "timestamp": "2026-09-11T12:00:00+00:00",
        "severity": "high",
        "detected_cves": [
            {
                "cve_id": cid,
                "confidence": conf,
                "affected_component": {
                    "layer": "application" if cid == "CVE-2023-0264" else "infrastructure"
                },
            }
            for cid in cve_ids
        ],
        "metrics": {"response_time_s": rt, "tokens": tokens, "cost_usd": cost},
    }


def _settings(tmp_path: Path):
    """Settings apuntando a un alerts.jsonl temporal y los escenarios reales."""
    return get_settings().model_copy(
        update={"alerts_dir": tmp_path, "scenarios_dir": SCENARIOS}
    )


def _write_alerts(tmp_path: Path, alerts: list[dict]) -> None:
    (tmp_path / "alerts.jsonl").write_text(
        "\n".join(json.dumps(a) for a in alerts), encoding="utf-8"
    )


def test_best_scenario_prefers_exact_then_specific() -> None:
    """Coincidencia exacta gana; ante intersección igual, el escenario más específico."""
    specs = [
        ("oidc", {"CVE-2023-0264"}),
        ("chained", {"CVE-2023-0264", "CVE-2026-33871"}),
    ]
    assert _best_scenario({"CVE-2023-0264"}, specs) == "oidc"
    assert _best_scenario({"CVE-2023-0264", "CVE-2026-33871"}, specs) == "chained"
    assert _best_scenario({"CVE-9999-0000"}, specs) is None


def test_evaluate_persisted_reads_agent_metrics(tmp_path: Path) -> None:
    """Tokens/costo/latencia salen de alert.metrics; el positivo detectado pasa."""
    _write_alerts(
        tmp_path,
        [
            _alert(["CVE-2023-0264"], tokens=30000, cost=0.0026, rt=21.2),
            _alert(["CVE-2026-33871"], tokens=31517, cost=0.0027, rt=29.6),
        ],
    )
    results = evaluate_persisted(_settings(tmp_path))
    by_id = {r.scenario_id: r for r in results}

    # Solo escenarios positivos CON evidencia; el encadenado (sin alerta combinada)
    # se omite en vez de contarse como fallo.
    assert all(r.scenario_type == "positive" for r in results)
    assert "cve-chained-standard" not in by_id
    assert set(by_id) == {"cve-2023-0264-basic", "cve-2026-33871-basic"}

    oidc = by_id["cve-2023-0264-basic"]
    assert oidc.passed  # detectó la CVE esperada
    assert oidc.tokens_used == 30000
    assert oidc.response_times_s == [21.2]
    assert oidc.analysis_ids == ["alert-cve-2023-0264"]

    dos = by_id["cve-2026-33871-basic"]
    assert dos.passed
    assert dos.tokens_used == 31517


def test_evaluate_persisted_no_double_count(tmp_path: Path) -> None:
    """Cada alerta se asigna a un solo escenario: el total no se infla."""
    _write_alerts(
        tmp_path,
        [_alert(["CVE-2023-0264"], tokens=10000, cost=0.001, rt=10.0)],
    )
    results = evaluate_persisted(_settings(tmp_path))
    total_tokens = sum(r.tokens_used for r in results)
    assert total_tokens == 10000  # no se cuenta en oidc-basic y chained a la vez


def test_evaluate_persisted_omits_unexercised(tmp_path: Path) -> None:
    """Un escenario sin evidencia (no ejercido) se omite, no se cuenta como fallo."""
    _write_alerts(
        tmp_path,
        [_alert(["CVE-2023-0264"], tokens=10000, cost=0.001, rt=10.0)],
    )
    results = evaluate_persisted(_settings(tmp_path))
    ids = {r.scenario_id for r in results}
    assert ids == {"cve-2023-0264-basic"}  # solo el que tiene alerta
    assert all(r.passed for r in results)  # y ese pasa


def test_evaluate_persisted_empty_when_no_alerts(tmp_path: Path) -> None:
    """Sin alertas persistidas no hay nada evaluable (no crashea, lista vacía)."""
    _write_alerts(tmp_path, [])
    results = evaluate_persisted(_settings(tmp_path))
    assert results == []
