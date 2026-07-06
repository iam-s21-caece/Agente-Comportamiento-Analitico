"""Tests del scenario_runner (lógica de comparación agente vs esperado)."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from validation.scenario_runner import run_scenario

SCENARIOS = Path(__file__).parent.parent / "validation" / "scenarios"


def _noop_runner(_path: Path) -> None:
    """Runner de scripts inerte (no ejecuta nada en los tests)."""
    return None


def _alerts(*alerts):
    """Crea un AlertProvider que devuelve las alertas dadas."""
    return lambda since, until: list(alerts)


def _cve_alert(cve_id: str, confidence: float, layer: str) -> dict:
    """Construye una alerta con una CVE detectada."""
    return {
        "severity": "high",
        "detected_cves": [
            {
                "cve_id": cve_id,
                "confidence": confidence,
                "affected_component": {"layer": layer},
            }
        ],
    }


def test_positive_scenario_passes_on_correct_detection() -> None:
    """Positivo OIDC con detección correcta debe pasar."""
    scenario = SCENARIOS / "positive" / "cve-2023-0264-basic"
    provider = _alerts(_cve_alert("CVE-2023-0264", 0.9, "application"))

    result = run_scenario(scenario, provider, run_script=_noop_runner)

    assert result.passed is True
    assert result.mismatches == []


def test_negative_scenario_fails_on_spurious_alert() -> None:
    """Negativo que produce alerta debe fallar (falso positivo)."""
    scenario = SCENARIOS / "negative" / "normal-single-user"
    provider = _alerts(_cve_alert("CVE-2023-0264", 0.9, "application"))

    result = run_scenario(scenario, provider, run_script=_noop_runner)

    assert result.passed is False
    assert any("falso positivo" in m.lower() for m in result.mismatches)


def test_negative_scenario_passes_when_silent() -> None:
    """Negativo sin alertas debe pasar."""
    scenario = SCENARIOS / "negative" / "normal-single-user"
    provider = _alerts()

    result = run_scenario(scenario, provider, run_script=_noop_runner)

    assert result.passed is True


def test_ambiguous_fails_when_firmly_labeled_known_cve() -> None:
    """Ambiguo encasillado en CVE conocida con alta confianza debe fallar."""
    scenario = SCENARIOS / "ambiguous" / "unknown-attack"
    provider = _alerts(_cve_alert("CVE-2023-0264", 0.9, "application"))

    result = run_scenario(scenario, provider, run_script=_noop_runner)

    assert result.passed is False


def test_ambiguous_passes_when_uncertain() -> None:
    """Ambiguo sin afirmación firme (incertidumbre) debe pasar."""
    scenario = SCENARIOS / "ambiguous" / "unknown-attack"
    # Alerta de baja confianza: no encasilla en la CVE conocida.
    provider = _alerts(_cve_alert("CVE-2023-0264", 0.3, "application"))

    result = run_scenario(scenario, provider, run_script=_noop_runner)

    assert result.passed is True
