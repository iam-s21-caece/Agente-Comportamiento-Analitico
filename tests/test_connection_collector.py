"""Tests del colector de conexiones (atribución de origen del DoS)."""

from __future__ import annotations

from pathlib import Path

from signal_collector.connection_collector import (
    ConnectionCollector,
    _decode_hex_ip,
    _hex_port,
    _scope,
)

# Contenido sintético al formato de /proc/net/tcp. Puerto local 20FB = 8443.
# 172.19.0.1 (gateway Docker) little-endian = 010013AC; 127.0.0.1 = 0100007F.
_PROC_TCP = """\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt
   0: 00000000:20FB 010013AC:C000 01 00000000:00000000 00:00000000 00000000
   1: 00000000:20FB 010013AC:C001 01 00000000:00000000 00:00000000 00000000
   2: 00000000:20FB 0100007F:D000 03 00000000:00000000 00:00000000 00000000
   3: 00000000:0050 010013AC:C002 01 00000000:00000000 00:00000000 00000000
   4: 00000000:20FB 08080808:C003 06 00000000:00000000 00:00000000 00000000
"""


def test_decode_hex_ip_v4() -> None:
    """La IP v4 se almacena little-endian en /proc/net/tcp."""
    assert _decode_hex_ip("0100007F", is_v6=False) == "127.0.0.1"
    assert _decode_hex_ip("010013AC", is_v6=False) == "172.19.0.1"


def test_hex_port_and_scope() -> None:
    """Puerto en hex y clasificación de alcance de la IP."""
    assert _hex_port("00000000:20FB") == 8443
    assert _scope("127.0.0.1") == "loopback"
    assert _scope("172.19.0.1") == "private"
    assert _scope("8.8.8.8") == "public"


def test_accumulate_filters_port_and_state(tmp_path: Path) -> None:
    """Solo cuenta conexiones ACTIVAS (01/03) al puerto de Keycloak (8443)."""
    proc_file = tmp_path / "tcp"
    proc_file.write_text(_PROC_TCP, encoding="utf-8")

    collector = ConnectionCollector()
    counts: dict[str, int] = {}
    collector._accumulate(str(proc_file), is_v6=False, counts=counts)

    # 172.19.0.1: dos conexiones ESTABLISHED al 8443. 127.0.0.1: una SYN_RECV.
    # El puerto 80 (línea 3) y el estado 06/TIME_WAIT (línea 4) se ignoran.
    assert counts == {"172.19.0.1": 2, "127.0.0.1": 1}


def test_snapshot_flags_masked_origin(tmp_path: Path, monkeypatch) -> None:
    """El top-talker privado/loopback marca ``masked`` y explica el NAT."""
    proc_file = tmp_path / "tcp"
    proc_file.write_text(_PROC_TCP, encoding="utf-8")
    empty = tmp_path / "tcp6"
    empty.write_text("  sl  local_address\n", encoding="utf-8")

    collector = ConnectionCollector()

    def fake_accumulate(path, is_v6, counts):  # noqa: ANN001
        real = str(proc_file) if not is_v6 else str(empty)
        ConnectionCollector._accumulate(collector, real, is_v6, counts)

    monkeypatch.setattr(collector, "_accumulate", fake_accumulate)
    snap = collector.collect()

    assert snap.total_connections == 3
    assert snap.top_talkers[0].ip == "172.19.0.1"
    assert snap.top_talkers[0].connections == 2
    assert snap.masked is True
    assert "enmascarada" in snap.note
