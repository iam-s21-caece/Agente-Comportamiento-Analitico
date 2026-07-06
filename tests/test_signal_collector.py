"""Tests de los colectores de señales (parseo y captura básica)."""

from __future__ import annotations

import json
from pathlib import Path

from signal_collector.base import KeycloakEvent
from signal_collector.container_metrics import _parse_size_to_mb
from signal_collector.h2_fallback import H2FallbackCollector
from signal_collector.host_metrics import HostMetricsCollector

FIXTURES = Path(__file__).parent / "fixtures"


def test_keycloak_event_from_admin_api_parses_fields() -> None:
    """El parseo del JSON de la Admin REST API debe poblar los campos clave."""
    raw = json.loads((FIXTURES / "events_takeover.json").read_text(encoding="utf-8"))
    event = KeycloakEvent.from_admin_api(raw[0])

    assert event.type == "LOGIN"
    assert event.user_id == "user-alice"
    assert event.session_id == "session-X"
    assert event.realm_id == "poc"
    assert event.time.year == 2026  # 1782302700000 ms -> 2026


def test_parse_size_to_mb_handles_units() -> None:
    """La conversión de tamaños de docker stats debe respetar las unidades."""
    assert _parse_size_to_mb("859MiB") == 859.0
    assert _parse_size_to_mb("1GiB") == 1024.0
    assert _parse_size_to_mb("512kB") == round(512 / 1024, 2)
    assert _parse_size_to_mb("basura") == 0.0


def test_h2_output_parser_extracts_events() -> None:
    """El parser del H2 Shell debe extraer filas de EVENT_ENTITY."""
    sample = (
        "EVENT_TIME | TYPE | REALM_ID | CLIENT_ID | USER_ID | SESSION_ID | IP_ADDRESS\n"
        "1782302700000 | LOGIN | poc | client1 | user-alice | session-X | 10.0.0.10\n"
        "1782302761000 | CODE_TO_TOKEN | poc | client1 | user-mallory | session-X | 10.0.0.20\n"
        "(2 rows)"
    )
    events = H2FallbackCollector._parse_h2_output(sample)

    assert len(events) == 2
    assert events[0].type == "LOGIN"
    assert events[1].type == "CODE_TO_TOKEN"
    assert events[1].session_id == "session-X"
    assert events[1].user_id == "user-mallory"


def test_host_collector_returns_structured_snapshot() -> None:
    """El colector de host debe devolver un snapshot poblado sin lanzar."""
    snapshot = HostMetricsCollector().collect()

    # En cualquier SO con psutil debe haber tasks y algún thread contabilizado.
    assert snapshot.total_tasks > 0
    assert snapshot.user_threads >= 0
    assert snapshot.error is None or isinstance(snapshot.error, str)
