"""Persistencia de alertas en un directorio de la VPS.

Cada alerta emitida se escribe en dos formatos dentro del directorio de salida
(montado como volumen del contenedor):

  * ``alerts.jsonl`` — una alerta por línea, acumulativo (ideal para la
    evaluación empírica y para agregaciones).
  * ``alert-<id>.json`` — un archivo legible por alerta.

Así las respuestas del agente quedan disponibles como archivos en la VPS, además
de los logs en stdout (``docker logs``).
"""

from __future__ import annotations

import json
from pathlib import Path

from config.logging_config import get_logger

from .schema import Alert

logger = get_logger(__name__)


class AlertSink:
    """Escribe alertas a un directorio en formato JSONL + archivo por alerta."""

    def __init__(self, alerts_dir: Path | str) -> None:
        """Inicializa el sink.

        Args:
            alerts_dir: directorio destino de las alertas.
        """
        self.dir = Path(alerts_dir)
        self.jsonl_path = self.dir / "alerts.jsonl"

    def write(self, alert: Alert) -> Path | None:
        """Persiste una alerta en disco.

        Args:
            alert: alerta a escribir.

        Returns:
            Ruta del archivo individual escrito, o ``None`` si falló la escritura.
        """
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            data = alert.model_dump(mode="json")
            line = json.dumps(data, ensure_ascii=False, default=str)

            # Acumulativo: una alerta por línea.
            with self.jsonl_path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")

            # Archivo legible por alerta.
            individual = self.dir / f"{alert.alert_id}.json"
            individual.write_text(
                json.dumps(data, ensure_ascii=False, indent=2, default=str),
                encoding="utf-8",
            )
            logger.info(
                "Alerta persistida",
                extra={"alert_id": alert.alert_id, "path": str(individual)},
            )
            return individual
        except OSError as exc:
            logger.error(
                "No se pudo persistir la alerta",
                extra={"alert_id": alert.alert_id, "error": str(exc)},
            )
            return None
