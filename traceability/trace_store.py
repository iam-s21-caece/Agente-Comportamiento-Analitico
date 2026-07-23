"""Persistencia de trazas en JSONL, organizada por fecha y ``analysis_id``.

Cada evento del ciclo agéntico se escribe como una línea JSON en
``<traces_dir>/<YYYY-MM-DD>/<analysis_id>.jsonl``. La escritura:

  * NO debe bloquear ni romper el flujo del agente si el disco falla → ante un
    error se bufferiza en memoria y se reintenta en la siguiente escritura;
  * aplica un tope de tamaño por evento (trunca strings largos) para que el
    chain-of-thought no genere trazas gigantes (decisión "completo con límite").
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from config.logging_config import get_logger

logger = get_logger(__name__)

# Marca visible cuando se trunca un string por exceder el tope.
_TRUNC_MARK = "…[+{n} chars truncados]"


class TraceStore:
    """Escritor append-only de trazas en JSONL con truncado y fallback."""

    def __init__(self, traces_dir: Path | str, max_event_bytes: int = 8192) -> None:
        """Inicializa el store.

        Args:
            traces_dir: directorio raíz de las trazas.
            max_event_bytes: tope de caracteres por string dentro de un evento.
        """
        self.dir = Path(traces_dir)
        self.max_event_bytes = max_event_bytes
        # Buffer de líneas que no se pudieron persistir (fallback ante fallo de
        # disco). Se reintenta en la siguiente escritura exitosa.
        self._fallback: list[tuple[Path, str]] = []

    def write(self, analysis_id: str, ts: datetime, event: dict[str, Any]) -> None:
        """Persiste un evento de traza.

        Nunca propaga excepciones: ante fallo de disco bufferiza y loguea.

        Args:
            analysis_id: id del análisis padre.
            ts: timestamp del evento (define la carpeta por fecha).
            event: contenido del evento (dict JSON-serializable).
        """
        try:
            safe = self._truncate(event)
            line = json.dumps(safe, ensure_ascii=False, default=str)
            path = self._path_for(analysis_id, ts)
            self._flush_fallback()
            self._append(path, line)
        except OSError as exc:
            logger.warning(
                "No se pudo persistir traza; se bufferiza",
                extra={"analysis_id": analysis_id, "error": str(exc)},
            )
            try:
                self._fallback.append((self._path_for(analysis_id, ts), line))
            except Exception:  # noqa: BLE001 - jamás romper el flujo del agente
                pass

    # ------------------------------------------------------------- internos
    def _path_for(self, analysis_id: str, ts: datetime) -> Path:
        """Ruta destino del archivo JSONL para un análisis y fecha."""
        day = ts.strftime("%Y-%m-%d")
        return self.dir / day / f"{analysis_id}.jsonl"

    @staticmethod
    def _append(path: Path, line: str) -> None:
        """Agrega una línea al archivo (creando carpetas si hace falta)."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    def _flush_fallback(self) -> None:
        """Reintenta escribir las líneas que quedaron en buffer."""
        if not self._fallback:
            return
        pending = self._fallback
        self._fallback = []
        for path, line in pending:
            try:
                self._append(path, line)
            except OSError:
                # Sigue sin poder escribir: vuelve al buffer.
                self._fallback.append((path, line))

    def _truncate(self, value: Any) -> Any:
        """Trunca recursivamente strings que superan el tope por evento.

        Args:
            value: valor arbitrario dentro del evento.

        Returns:
            El valor con los strings largos truncados y marcados.
        """
        limit = self.max_event_bytes
        if isinstance(value, str):
            if len(value) > limit:
                return value[:limit] + _TRUNC_MARK.format(n=len(value) - limit)
            return value
        if isinstance(value, dict):
            return {k: self._truncate(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self._truncate(v) for v in value]
        return value
