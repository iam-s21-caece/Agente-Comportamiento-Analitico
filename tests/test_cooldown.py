"""Tests de la firma de cooldown (deduplicación de alertas)."""

from __future__ import annotations

from deterministic_checks.base import CheckResult
from main import compute_trigger_signature


def _oidc_result(session_ids: list[str]) -> CheckResult:
    """CheckResult OIDC con las anomalías de los session_ids dados."""
    return CheckResult(
        check_id="oidc_session_reuse",
        name="oidc",
        cve_id="CVE-2023-0264",
        triggered=True,
        evidence={"anomalies": [{"session_id": s} for s in session_ids]},
    )


def test_signature_stable_across_duplicate_counts() -> None:
    """La firma NO debe cambiar si el mismo takeover aparece 1 o 2 veces.

    Este era el bug: con duplicados, la firma cambiaba y el cooldown no
    matcheaba, re-alertando y gastando tokens en cada ciclo.
    """
    one = compute_trigger_signature([_oidc_result(["sess-X"])])
    two = compute_trigger_signature([_oidc_result(["sess-X", "sess-X"])])

    assert one == two == "oidc:sess-X"


def test_signature_distinguishes_new_attack() -> None:
    """Una sesión distinta (ataque nuevo) debe producir otra firma."""
    a = compute_trigger_signature([_oidc_result(["sess-X"])])
    b = compute_trigger_signature([_oidc_result(["sess-Y"])])

    assert a != b


def test_signature_for_dos_uses_check_id() -> None:
    """El DoS se firma por episodio (check_id)."""
    dos = CheckResult(
        check_id="dos_thresholds",
        name="dos",
        cve_id="CVE-2026-33871",
        triggered=True,
    )
    assert compute_trigger_signature([dos]) == "dos_thresholds"
