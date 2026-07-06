"""Modelos de datos comunes y la interfaz base de los colectores de señales.

Un *colector* observa una porción del mundo (host, contenedor, eventos de
Keycloak) y devuelve un snapshot estructurado. Estos snapshots alimentan tanto
los checks deterministas como el contexto del bucle ReAct.
"""

from __future__ import annotations

import abc
from datetime import datetime, timezone
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, Field


def _now() -> datetime:
    """Devuelve el instante actual en UTC (con tzinfo)."""
    return datetime.now(timezone.utc)


class JvmProcessInfo(BaseModel):
    """Información del proceso JVM de Keycloak."""

    pid: int
    virt_mb: float = Field(description="Memoria virtual (VIRT) en MB.")
    res_mb: float = Field(description="Resident Set Size (RES) en MB.")
    shr_kb: float = Field(description="Memoria compartida (SHR) en KB.")
    state: str = Field(description="Estado del proceso (p.ej. 'S', 'R').")
    num_threads: int = 0
    cpu_percent: float = 0.0


class HostMetricsSnapshot(BaseModel):
    """Snapshot de métricas del host y de la JVM de Keycloak."""

    timestamp: datetime = Field(default_factory=_now)
    cpu_percent: float = 0.0
    total_tasks: int = 0
    user_threads: int = 0
    kernel_threads: int = 0
    jvm: JvmProcessInfo | None = None
    error: str | None = None


class ContainerMetricsSnapshot(BaseModel):
    """Snapshot de métricas del contenedor de Keycloak (docker stats)."""

    timestamp: datetime = Field(default_factory=_now)
    name: str = ""
    cpu_percent: float = 0.0
    mem_usage_mb: float = 0.0
    mem_limit_mb: float = 0.0
    mem_percent: float = 0.0
    pids: int = 0
    error: str | None = None


class KeycloakEvent(BaseModel):
    """Evento de autenticación de Keycloak (EVENT_ENTITY / Admin REST API)."""

    time: datetime
    type: str
    realm_id: str | None = None
    client_id: str | None = None
    user_id: str | None = None
    session_id: str | None = None
    ip_address: str | None = None
    error: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_admin_api(cls, raw: dict[str, Any]) -> "KeycloakEvent":
        """Construye un evento desde el JSON de la Admin REST API.

        Args:
            raw: objeto JSON tal como lo devuelve ``GET .../events``.

        Returns:
            KeycloakEvent normalizado.
        """
        millis = raw.get("time", 0)
        ts = datetime.fromtimestamp(millis / 1000.0, timezone.utc) if millis else _now()
        details = raw.get("details", {}) or {}
        return cls(
            time=ts,
            type=raw.get("type", "UNKNOWN"),
            realm_id=raw.get("realmId"),
            client_id=raw.get("clientId"),
            user_id=raw.get("userId"),
            session_id=raw.get("sessionId"),
            ip_address=raw.get("ipAddress"),
            error=raw.get("error"),
            details=details,
        )


T = TypeVar("T", bound=BaseModel)


class SignalCollector(abc.ABC, Generic[T]):
    """Interfaz común a todos los colectores de señales."""

    @abc.abstractmethod
    def collect(self) -> T:
        """Captura y devuelve un snapshot estructurado.

        Returns:
            Un modelo Pydantic con la señal capturada. Las implementaciones no
            deben lanzar excepciones hacia afuera: capturan el error en el campo
            ``error`` del snapshot correspondiente.
        """
        raise NotImplementedError
