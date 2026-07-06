"""Tests de los checks deterministas (correlación OIDC y umbrales DoS)."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from deterministic_checks.dos_thresholds import Baseline, DosThresholdCheck
from deterministic_checks.oidc_correlation import OidcCorrelationCheck
from knowledge_base.loader import CveDefinition
from signal_collector.base import HostMetricsSnapshot, JvmProcessInfo, KeycloakEvent

FIXTURES = Path(__file__).parent / "fixtures"
CVES_DIR = Path(__file__).parent.parent / "knowledge_base" / "cves"

# Ventana enorme para que los timestamps fijos de las fixtures no se filtren por
# la ventana temporal, independientemente del reloj de la máquina de test.
HUGE_WINDOW = 10_000_000


def _load_events(name: str) -> list[KeycloakEvent]:
    """Carga eventos desde una fixture JSON (formato Admin REST API)."""
    raw = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    return [KeycloakEvent.from_admin_api(item) for item in raw]


def _load_cve(filename: str) -> CveDefinition:
    """Carga una definición de CVE desde su YAML."""
    data = yaml.safe_load((CVES_DIR / filename).read_text(encoding="utf-8"))
    return CveDefinition.model_validate(data)


def test_oidc_detects_session_takeover() -> None:
    """Reuse de session_id entre alice y mallory debe disparar la anomalía."""
    cve = _load_cve("cve-2023-0264.yaml")
    check = OidcCorrelationCheck(cve)
    events = _load_events("events_takeover.json")

    results = check.run(events=events, window_minutes=HUGE_WINDOW)
    result = results[0]

    assert result.triggered is True
    assert result.severity == "critical"
    anomalies = result.evidence["anomalies"]
    assert len(anomalies) == 1
    assert anomalies[0]["victim_user_id"] == "user-alice"
    assert anomalies[0]["attacker_user_id"] == "user-mallory"
    assert anomalies[0]["session_id"] == "session-X"


def test_oidc_detects_real_session_reuse_materialization() -> None:
    """Forma real de CVE-2023-0264: el CODE_TO_TOKEN reutiliza la sesión de la
    víctima justo después del LOGIN del atacante (con otra sesión). El evento
    queda registrado con el user de la víctima, por eso se detecta por el cambio
    de sesión respecto del login más reciente, no por mismatch de user directo.
    """
    cve = _load_cve("cve-2023-0264.yaml")
    check = OidcCorrelationCheck(cve)
    events = _load_events("events_takeover_real.json")

    results = check.run(events=events, window_minutes=HUGE_WINDOW)
    result = results[0]

    assert result.triggered is True
    anomalies = result.evidence["anomalies"]
    assert len(anomalies) == 1
    assert anomalies[0]["form"] == "session_reuse"
    assert anomalies[0]["victim_user_id"] == "user-alice"
    assert anomalies[0]["attacker_user_id"] == "user-mallory"
    assert anomalies[0]["session_id"] == "session-X"


def test_oidc_normal_traffic_does_not_trigger() -> None:
    """Tráfico normal (cada usuario con su propio session_id) no dispara."""
    cve = _load_cve("cve-2023-0264.yaml")
    check = OidcCorrelationCheck(cve)
    events = _load_events("events_normal.json")

    results = check.run(events=events, window_minutes=HUGE_WINDOW)

    assert results[0].triggered is False
    assert results[0].evidence["anomalies"] == []


def _baseline() -> Baseline:
    """Baseline de estado normal para los tests de DoS."""
    return Baseline(
        values={
            "host_cpu_percent": 12.0,
            "total_tasks": 40.0,
            "user_threads": 200.0,
            "kernel_threads": 70.0,
            "jvm_res_mb": 500.0,
            "jvm_virt_mb": 2500.0,
            "jvm_num_threads": 45.0,
            "jvm_cpu_percent": 5.0,
        }
    )


def _attack_snapshot() -> HostMetricsSnapshot:
    """Snapshot que reproduce la firma volumétrica del DoS."""
    return HostMetricsSnapshot(
        cpu_percent=99.0,
        total_tasks=58,
        user_threads=437,
        kernel_threads=72,
        jvm=JvmProcessInfo(
            pid=1234, virt_mb=3671, res_mb=859, shr_kb=29680, state="S",
            num_threads=437, cpu_percent=180.0
        ),
    )


def _normal_snapshot() -> HostMetricsSnapshot:
    """Snapshot de estado normal."""
    return HostMetricsSnapshot(
        cpu_percent=14.0,
        total_tasks=41,
        user_threads=210,
        kernel_threads=70,
        jvm=JvmProcessInfo(
            pid=1234, virt_mb=2550, res_mb=520, shr_kb=29000, state="S",
            num_threads=55, cpu_percent=8.0
        ),
    )


def test_dos_triggers_only_when_sustained() -> None:
    """El DoS debe dispararse solo tras 'sustained_samples' breaches seguidos."""
    cve = _load_cve("cve-2026-33871.yaml")
    check = DosThresholdCheck(cve, _baseline())
    snapshot = _attack_snapshot()

    # sustained_samples = 3 en el YAML: primeras dos no confirman.
    first = check.run(host_snapshot=snapshot)[0]
    second = check.run(host_snapshot=snapshot)[0]
    assert first.triggered is False
    assert second.triggered is False

    third = check.run(host_snapshot=snapshot)[0]
    assert third.triggered is True
    assert third.severity == "high"
    assert len(third.evidence["sustained_breaches"]) >= 2


def test_dos_normal_state_does_not_trigger() -> None:
    """Estado normal sostenido nunca debe disparar el check de DoS."""
    cve = _load_cve("cve-2026-33871.yaml")
    check = DosThresholdCheck(cve, _baseline())
    snapshot = _normal_snapshot()

    triggered = any(check.run(host_snapshot=snapshot)[0].triggered for _ in range(5))
    assert triggered is False
