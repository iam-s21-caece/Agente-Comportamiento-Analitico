"""Logger de auditoría estructurado, separado del logging operativo.

Emite una línea JSON por evento del ciclo agéntico bajo el logger ``audit``,
correlacionada con las trazas vía ``analysis_id`` / ``event_id`` compartidos. No
incluye payloads voluminosos (eso vive en las trazas); solo los identificadores
y el tipo de evento, para una auditoría liviana y cruzable.
"""

from __future__ import annotations

import logging
from typing import Any

# Atributos reservados de LogRecord: NUNCA usarlos como clave de `extra`
# (colisionan y hacen crashear el logging).
_RESERVED = {"args", "msg", "name", "levelname", "module", "message"}


class AuditLogger:
    """Logger de auditoría con correlación por ids."""

    def __init__(self, name: str = "audit") -> None:
        """Inicializa el logger de auditoría.

        Args:
            name: nombre del logger dedicado (separado del operativo).
        """
        self.logger = logging.getLogger(name)

    def event(
        self,
        analysis_id: str,
        event_id: str,
        event_type: str,
        seq: int,
        **fields: Any,
    ) -> None:
        """Registra un evento de auditoría.

        Args:
            analysis_id: id del análisis padre.
            event_id: id único del evento (correlaciona con la traza).
            event_type: tipo de evento del ciclo agéntico.
            seq: número de secuencia dentro del análisis.
            **fields: metadatos livianos adicionales (sin payloads grandes).
        """
        safe = {k: v for k, v in fields.items() if k not in _RESERVED}
        self.logger.info(
            "audit_event",
            extra={
                "audit": True,
                "analysis_id": analysis_id,
                "event_id": event_id,
                "event_type": event_type,
                "seq": seq,
                **safe,
            },
        )
