"""Consulta de trazas persistidas.

Provee lectura perezosa (iteradores) de las trazas en disco, filtrando por
rango temporal, tipo de evento, ``analysis_id``, CVE y contenido. No carga todo
en memoria: recorre los archivos JSONL línea por línea.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any


def _iter_files(traces_dir: Path, analysis_id: str | None, date: str | None) -> Iterator[Path]:
    """Itera los archivos JSONL de trazas que matchean fecha/análisis.

    Args:
        traces_dir: directorio raíz de trazas.
        analysis_id: si se da, solo archivos de ese análisis.
        date: si se da (``YYYY-MM-DD``), solo esa carpeta de fecha.

    Yields:
        Rutas de archivos ``.jsonl`` candidatos.
    """
    if not traces_dir.exists():
        return
    day_dirs = [traces_dir / date] if date else sorted(traces_dir.glob("*"))
    for day_dir in day_dirs:
        if not day_dir.is_dir():
            continue
        pattern = f"{analysis_id}.jsonl" if analysis_id else "*.jsonl"
        for path in sorted(day_dir.glob(pattern)):
            yield path


def iter_events(
    traces_dir: Path | str,
    analysis_id: str | None = None,
    date: str | None = None,
    event_type: str | None = None,
    cve: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
) -> Iterator[dict[str, Any]]:
    """Itera eventos de traza que cumplen los criterios dados.

    Args:
        traces_dir: directorio raíz de trazas.
        analysis_id: filtra por análisis.
        date: filtra por fecha (``YYYY-MM-DD``).
        event_type: filtra por tipo de evento.
        cve: filtra eventos que mencionen esa CVE (búsqueda en el contenido).
        since: límite temporal inferior (inclusive).
        until: límite temporal superior (inclusive).

    Yields:
        Eventos de traza como dicts, en orden de archivo.
    """
    root = Path(traces_dir)
    for path in _iter_files(root, analysis_id, date):
        try:
            with path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if _matches(event, event_type, cve, since, until):
                        yield event
        except OSError:
            continue


def get_analysis_events(
    traces_dir: Path | str, analysis_id: str
) -> Iterator[dict[str, Any]]:
    """Itera todos los eventos de un análisis (en cualquier fecha).

    Args:
        traces_dir: directorio raíz de trazas.
        analysis_id: id del análisis a recuperar.

    Yields:
        Eventos del análisis, ordenados por secuencia.
    """
    events = list(iter_events(traces_dir, analysis_id=analysis_id))
    events.sort(key=lambda e: e.get("seq", 0))
    yield from events


def _matches(
    event: dict[str, Any],
    event_type: str | None,
    cve: str | None,
    since: datetime | None,
    until: datetime | None,
) -> bool:
    """Evalúa si un evento cumple los filtros.

    Args:
        event: evento de traza.
        event_type: tipo requerido, o ``None``.
        cve: CVE requerida en el contenido, o ``None``.
        since: límite inferior temporal, o ``None``.
        until: límite superior temporal, o ``None``.

    Returns:
        ``True`` si el evento pasa todos los filtros activos.
    """
    if event_type and event.get("event_type") != event_type:
        return False
    if cve and cve.upper() not in json.dumps(event, default=str).upper():
        return False
    if since or until:
        ts_raw = event.get("timestamp")
        if ts_raw:
            try:
                ts = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
                if since and ts < since:
                    return False
                if until and ts > until:
                    return False
            except ValueError:
                pass
    return True
