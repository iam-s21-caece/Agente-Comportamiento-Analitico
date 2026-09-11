"""Panel de diagnóstico: mensajes ESPECÍFICOS y accionables del agente.

Expone un snapshot del estado de los chequeos clave (eventos de Keycloak, JVM,
baseline, dashboard, LLM/conectividad) para que el dashboard los muestre y no haya
que bucear en los logs buscando por qué algo no anda. Es CURADO: solo mensajes con
sentido operativo, deduplicados por código (se guarda el estado ACTUAL de cada uno,
no un log creciente). Regla de oro: nunca propaga excepciones al agente.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from config.logging_config import get_logger
from config.settings import Settings, get_settings

logger = get_logger(__name__)

Level = Literal["ok", "warn", "error"]
_ORDER = {"error": 0, "warn": 1, "ok": 2}


class Diagnostics:
    """Mantiene y persiste el estado actual de los diagnósticos del agente."""

    def __init__(self, path: Path | str) -> None:
        """Inicializa el diagnóstico.

        Args:
            path: archivo JSON donde se persiste el snapshot.
        """
        self._path = Path(path)
        self._items: dict[str, dict] = {}
        self._lock = threading.Lock()

    def report(self, code: str, level: Level, message: str, hint: str = "") -> None:
        """Registra (o actualiza) el estado de un diagnóstico por su código.

        Args:
            code: identificador estable del chequeo (p. ej. ``keycloak_events``).
            level: ``ok`` | ``warn`` | ``error``.
            message: mensaje específico y legible.
            hint: sugerencia accionable (qué hacer para resolverlo).
        """
        try:
            with self._lock:
                self._items[code] = {
                    "code": code,
                    "level": level,
                    "message": message,
                    "hint": hint,
                    "at": datetime.now(timezone.utc).isoformat(),
                }
                self._flush()
        except Exception as exc:  # noqa: BLE001 - el diagnóstico no debe romper nada
            logger.warning("No se pudo registrar diagnóstico", extra={"error": str(exc)})

    def _flush(self) -> None:
        """Escribe el snapshot ordenado (error > warn > ok) de forma atómica."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        items = sorted(
            self._items.values(), key=lambda i: (_ORDER.get(i["level"], 3), i["code"])
        )
        snapshot = {
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "items": items,
        }
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(self._path)  # atómico: el dashboard nunca lee un archivo a medias


_singleton: Diagnostics | None = None


def get_diagnostics(settings: Settings | None = None) -> Diagnostics:
    """Devuelve el ``Diagnostics`` global (singleton), creándolo si hace falta."""
    global _singleton
    if _singleton is None:
        cfg = settings or get_settings()
        _singleton = Diagnostics(cfg.diagnostics_path)
    return _singleton
