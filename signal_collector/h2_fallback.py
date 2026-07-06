"""Fallback de eventos vía acceso directo a la base H2 (docker exec).

Se usa SOLO si la Admin REST API no resulta viable. Ejecuta el H2 Shell dentro
del contenedor de Keycloak y parsea la salida tabular de la consulta sobre
``EVENT_ENTITY``. El acceso fue verificado por el investigador.
"""

from __future__ import annotations

import subprocess
from datetime import datetime, timezone

from config.logging_config import get_logger
from config.settings import Settings, get_settings

from .base import KeycloakEvent

logger = get_logger(__name__)

# Tipos de evento de interés para la correlación OIDC.
_DEFAULT_EVENT_TYPES = ("LOGIN", "LOGOUT", "CODE_TO_TOKEN", "REFRESH_TOKEN")


class H2FallbackCollector:
    """Lee eventos desde la base H2 interna de Keycloak vía ``docker exec``."""

    def __init__(self, settings: Settings | None = None) -> None:
        """Inicializa el colector de fallback.

        Args:
            settings: configuración; si se omite se usa la global.
        """
        self.settings = settings or get_settings()

    def get_events(
        self, event_types: tuple[str, ...] = _DEFAULT_EVENT_TYPES
    ) -> list[KeycloakEvent]:
        """Consulta EVENT_ENTITY filtrando por tipo y devuelve eventos.

        Args:
            event_types: tipos de evento a incluir en el ``WHERE``.

        Returns:
            Lista de eventos parseados, o lista vacía ante cualquier error.
        """
        types_in = ", ".join(f"'{t}'" for t in event_types)
        sql = (
            "SELECT EVENT_TIME, TYPE, REALM_ID, CLIENT_ID, USER_ID, SESSION_ID, "
            "IP_ADDRESS FROM EVENT_ENTITY "
            f"WHERE TYPE IN ({types_in}) ORDER BY EVENT_TIME ASC;"
        )
        # Resolución del jar H2 vía shell glob dentro del contenedor.
        inner = (
            "java -cp $(ls "
            f"{self.settings.h2_jar_glob}) org.h2.tools.Shell "
            f'-url "{self.settings.h2_jdbc_url}" '
            f"-user {self.settings.h2_user} -password {self.settings.h2_password} "
            f'-sql "{sql}"'
        )
        cmd = [
            "docker",
            "exec",
            self.settings.container_name,
            "bash",
            "-lc",
            inner,
        ]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30, check=True
            )
        except (subprocess.SubprocessError, FileNotFoundError) as exc:
            logger.error("Fallback H2 falló", extra={"error": str(exc)})
            return []

        return self._parse_h2_output(result.stdout)

    @staticmethod
    def _parse_h2_output(output: str) -> list[KeycloakEvent]:
        """Parsea la salida tabular del H2 Shell.

        El H2 Shell separa columnas con ``|``. La primera fila es el header y la
        última suele indicar el conteo de filas; ambas se descartan.

        Args:
            output: stdout del H2 Shell.

        Returns:
            Lista de ``KeycloakEvent``.
        """
        events: list[KeycloakEvent] = []
        lines = [ln for ln in output.splitlines() if "|" in ln]
        if not lines:
            return events

        header = [h.strip().upper() for h in lines[0].split("|")]
        idx = {name: i for i, name in enumerate(header)}
        for line in lines[1:]:
            cols = [c.strip() for c in line.split("|")]
            if len(cols) != len(header):
                continue
            try:
                raw_time = cols[idx.get("EVENT_TIME", 0)]
                millis = int(raw_time) if raw_time.isdigit() else 0
                ts = (
                    datetime.fromtimestamp(millis / 1000.0, timezone.utc)
                    if millis
                    else datetime.now(timezone.utc)
                )
                events.append(
                    KeycloakEvent(
                        time=ts,
                        type=cols[idx["TYPE"]],
                        realm_id=_nz(cols[idx.get("REALM_ID", -1)]),
                        client_id=_nz(cols[idx.get("CLIENT_ID", -1)]),
                        user_id=_nz(cols[idx.get("USER_ID", -1)]),
                        session_id=_nz(cols[idx.get("SESSION_ID", -1)]),
                        ip_address=_nz(cols[idx.get("IP_ADDRESS", -1)]),
                    )
                )
            except (KeyError, IndexError, ValueError):
                continue
        return events


def _nz(value: str | None) -> str | None:
    """Normaliza cadenas vacías o 'null' a ``None``.

    Args:
        value: valor crudo de la columna.

    Returns:
        El valor, o ``None`` si está vacío/es nulo.
    """
    if value is None:
        return None
    value = value.strip()
    if not value or value.lower() == "null":
        return None
    return value
