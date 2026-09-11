"""Tests del panel de diagnóstico y del estampado de métricas en la alerta."""

from __future__ import annotations

import json
from pathlib import Path

from alert_builder.schema import Alert
from diagnostics import Diagnostics


def test_diagnostics_snapshot_upserts_and_orders(tmp_path: Path) -> None:
    """Reportar upsertea por código y ordena error > warn > ok."""
    path = tmp_path / "diagnostics.json"
    diag = Diagnostics(path)
    diag.report("keycloak_events", "ok", "Eventos habilitados (5 en 24h)")
    diag.report("jvm", "warn", "JVM no detectada", "Ajustá JVM_CMDLINE_MATCH.")
    diag.report("keycloak_events", "error", "Eventos NO habilitados", "Activá Save events.")

    snap = json.loads(path.read_text(encoding="utf-8"))
    items = snap["items"]
    # keycloak_events quedó en 'error' (upsert, no duplicado) y va primero.
    assert len(items) == 2
    assert items[0]["code"] == "keycloak_events" and items[0]["level"] == "error"
    assert items[0]["hint"] == "Activá Save events."
    assert items[1]["code"] == "jvm" and items[1]["level"] == "warn"


def test_diagnostics_never_raises(tmp_path: Path) -> None:
    """Un path inválido no debe propagar excepción (observación no rompe el agente)."""
    diag = Diagnostics(tmp_path / "no" / "such" / "dir" / "d.json")
    diag._path = Path("\0invalid")  # fuerza fallo de escritura
    diag.report("x", "ok", "y")  # no debe lanzar


def test_alert_carries_agent_metrics() -> None:
    """La alerta lleva las métricas observacionales estampadas por el agente."""
    alert = Alert()
    assert alert.metrics.response_time_s is None  # default
    alert.metrics.response_time_s = 12.3
    alert.metrics.tokens = 4200
    alert.metrics.cost_usd = 0.0012
    dumped = alert.model_dump(mode="json")
    assert dumped["metrics"]["response_time_s"] == 12.3
    assert dumped["metrics"]["tokens"] == 4200
