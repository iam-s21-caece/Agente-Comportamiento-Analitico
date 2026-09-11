"""Configuración de logging estructurado (JSON) para el agente.

Se prioriza salida JSON para poder analizar post-hoc cada paso del bucle ReAct
y cada captura de señales. El nivel y formato son configurables por entorno.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any


class JsonFormatter(logging.Formatter):
    """Formateador que emite cada registro como una línea JSON."""

    # Atributos estándar de LogRecord que no son "extras" del usuario.
    _RESERVED = set(
        logging.makeLogRecord({}).__dict__.keys()
    ) | {"message", "asctime", "taskName"}

    def format(self, record: logging.LogRecord) -> str:
        """Serializa el registro a JSON.

        Args:
            record: registro de logging a formatear.

        Returns:
            str: representación JSON en una sola línea.
        """
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)

        # Adjuntar extras pasados vía logger.info(..., extra={...}).
        for key, value in record.__dict__.items():
            if key not in self._RESERVED and not key.startswith("_"):
                payload[key] = _safe(value)

        return json.dumps(payload, ensure_ascii=False, default=str)


def _safe(value: Any) -> Any:
    """Convierte valores no serializables a algo representable en JSON."""
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError):
        return str(value)


def setup_logging(level: str = "INFO", fmt: str = "json") -> None:
    """Configura el logging raíz del proceso.

    Args:
        level: nivel de logging (``DEBUG``, ``INFO``, ...).
        fmt: ``"json"`` para salida estructurada o ``"plain"`` para texto.
    """
    handler = logging.StreamHandler(stream=sys.stdout)
    if fmt == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        )

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level.upper())

    # Silenciar ruido de librerías HTTP en niveles bajos.
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Devuelve un logger con el nombre dado.

    Args:
        name: nombre del logger (habitualmente ``__name__``).

    Returns:
        logging.Logger: logger configurado.
    """
    return logging.getLogger(name)
