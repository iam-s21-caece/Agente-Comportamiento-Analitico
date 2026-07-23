"""Tests de la capa de trazabilidad (store, recorder y query)."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from traceability.trace_query import get_analysis_events, iter_events
from traceability.trace_recorder import TraceRecorder
from traceability.trace_store import TraceStore


def _store(tmp_path: Path, max_bytes: int = 8192) -> TraceStore:
    """Crea un TraceStore apuntando a un directorio temporal."""
    return TraceStore(tmp_path / "traces", max_event_bytes=max_bytes)


def test_store_writes_jsonl_by_date_and_analysis(tmp_path: Path) -> None:
    """El store debe escribir en <fecha>/<analysis_id>.jsonl."""
    store = _store(tmp_path)
    ts = datetime(2026, 7, 2, 12, 0, tzinfo=timezone.utc)
    store.write("an-abc", ts, {"event_type": "iteration", "payload": {"iteration": 1}})

    expected = tmp_path / "traces" / "2026-07-02" / "an-abc.jsonl"
    assert expected.exists()
    assert "iteration" in expected.read_text(encoding="utf-8")


def test_store_truncates_long_strings(tmp_path: Path) -> None:
    """Los strings que superan el tope se truncan y se marcan."""
    store = _store(tmp_path, max_bytes=50)
    ts = datetime(2026, 7, 2, 12, 0, tzinfo=timezone.utc)
    long_text = "x" * 500
    store.write("an-trunc", ts, {"event_type": "llm_thought", "payload": {"thought": long_text}})

    content = (tmp_path / "traces" / "2026-07-02" / "an-trunc.jsonl").read_text(
        encoding="utf-8"
    )
    assert "truncados" in content
    assert ("x" * 500) not in content  # el texto completo no debe estar


def test_recorder_records_full_cycle(tmp_path: Path) -> None:
    """El recorder registra inicio, iteración, thought, tool y alerta."""
    store = _store(tmp_path)
    recorder = TraceRecorder(store=store)
    aid = recorder.new_analysis_id()

    recorder.start_analysis(aid, "estado inicial")
    recorder.record_iteration(aid, 1)
    recorder.record_thought(aid, 1, "razonando...")
    recorder.record_tool_call(aid, 1, "get_host_metrics_snapshot", {})
    recorder.record_tool_result(aid, 1, "get_host_metrics_snapshot", {"cpu": 10})
    recorder.record_alert(aid, {"alert_id": "alert-x", "severity": "high"})
    recorder.end_analysis(aid, 1)

    events = list(get_analysis_events(tmp_path / "traces", aid))
    types = [e["event_type"] for e in events]
    assert types == [
        "analysis_start",
        "iteration",
        "llm_thought",
        "tool_call",
        "tool_result",
        "alert_emitted",
        "analysis_end",
    ]
    # La secuencia debe ser monótona creciente.
    assert [e["seq"] for e in events] == list(range(len(events)))


def test_recorder_never_raises_on_store_failure() -> None:
    """Si el store falla, el recorder no propaga la excepción."""

    class BrokenStore:
        def write(self, *_args, **_kwargs):
            raise OSError("disco lleno")

    recorder = TraceRecorder(store=BrokenStore())  # type: ignore[arg-type]
    aid = recorder.new_analysis_id()
    # No debe lanzar aunque el store explote.
    recorder.start_analysis(aid, "x")
    recorder.record_iteration(aid, 1)


def test_query_filters_by_event_type(tmp_path: Path) -> None:
    """iter_events filtra por tipo de evento."""
    store = _store(tmp_path)
    recorder = TraceRecorder(store=store)
    aid = recorder.new_analysis_id()
    recorder.start_analysis(aid, "x")
    recorder.record_tool_call(aid, 1, "run_deterministic_check", {"check_id": "dos_thresholds"})
    recorder.record_tool_result(aid, 1, "run_deterministic_check", {"results": []})

    checks = list(iter_events(tmp_path / "traces", event_type="check_result"))
    assert len(checks) == 1
    assert checks[0]["payload"]["tool"] == "run_deterministic_check"
