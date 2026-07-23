"""Colector de eventos de Keycloak vía Admin REST API.

Obtiene un access token con credenciales admin (password grant sobre el realm
``master``) y consulta ``GET /admin/realms/{realm}/events`` con filtros por tipo
de evento y rango temporal. Es la vía PREFERENTE (JSON estructurado) frente al
acceso directo a la base H2.

TLS: el entorno de investigación usa certificados self-signed, por lo que las
llamadas usan ``verify=False`` de forma deliberada y declarada. NO debe usarse
``verify=True`` contra esta instancia.
"""

from __future__ import annotations

import warnings
from datetime import datetime, timezone

import requests
import urllib3

from config.logging_config import get_logger
from config.settings import Settings, get_settings

from .base import KeycloakEvent

logger = get_logger(__name__)

# Silenciar el warning de verificación TLS deshabilitada: es una decisión
# consciente del entorno controlado de investigación (certs self-signed).
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class KeycloakEventsCollector:
    """Cliente de la Admin REST API de Keycloak para eventos de autenticación."""

    def __init__(self, settings: Settings | None = None) -> None:
        """Inicializa el cliente.

        Args:
            settings: configuración; si se omite se usa la global.
        """
        self.settings = settings or get_settings()
        self._token: str | None = None
        # Epoch (segundos) en que el token cacheado deja de considerarse válido.
        self._token_expiry: float = 0.0

    # ------------------------------------------------------------------ auth
    def _get_access_token(self, force_refresh: bool = False) -> str:
        """Obtiene (o reutiliza) un access token de administrador.

        Args:
            force_refresh: si ``True`` ignora el token cacheado.

        Returns:
            Access token como string.

        Raises:
            requests.RequestException: si la autenticación falla.
        """
        import time

        # Refresco proactivo: si el token sigue vigente (con margen), reutilizarlo.
        # Evita el 401 periódico por vencimiento (~60s de vida del access token).
        if self._token and not force_refresh and time.time() < self._token_expiry:
            return self._token

        data = {
            "grant_type": "password",
            "client_id": self.settings.keycloak_admin_client_id,
            "username": self.settings.keycloak_admin_user,
            "password": self.settings.keycloak_admin_password,
        }
        # verify=False: certificados self-signed del entorno de investigación.
        resp = requests.post(
            self.settings.token_endpoint,
            data=data,
            verify=self.settings.tls_verify,
            timeout=self.settings.http_timeout_seconds,
        )
        resp.raise_for_status()
        payload = resp.json()
        self._token = payload["access_token"]
        # Renovar 30s antes del vencimiento real (mínimo 10s de validez).
        expires_in = int(payload.get("expires_in", 60))
        self._token_expiry = time.time() + max(10, expires_in - 30)
        return self._token

    # ---------------------------------------------------------------- events
    def get_events(
        self,
        event_types: list[str] | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        max_results: int = 1000,
        realm: str | None = None,
    ) -> list[KeycloakEvent]:
        """Consulta eventos de Keycloak con filtros opcionales.

        Args:
            event_types: tipos a filtrar (p.ej. ``["LOGIN", "CODE_TO_TOKEN"]``).
            since: límite inferior temporal (inclusive).
            until: límite superior temporal (inclusive).
            max_results: tope de resultados a pedir.
            realm: realm a consultar; por defecto el configurado.

        Returns:
            Lista de eventos normalizados, ordenados por tiempo ascendente. Ante
            un error de red/HTTP devuelve lista vacía (no propaga excepciones).
        """
        params: dict[str, object] = {"max": max_results}
        if event_types:
            params["type"] = event_types
        if since:
            params["dateFrom"] = since.strftime("%Y-%m-%d")
        if until:
            params["dateTo"] = until.strftime("%Y-%m-%d")

        try:
            events = self._request_events(params, realm)
        except requests.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else None
            # Reintentar una sola vez con token fresco ante 401. El refresh se
            # hace DENTRO del try para que un 401 persistente (p.ej. credenciales
            # admin incorrectas) no propague y tumbe el proceso: se loguea y se
            # devuelve lista vacía, manteniendo vivo el modo continuous.
            if status == 401:
                logger.warning(
                    "401 al consultar eventos; reintentando con token fresco"
                )
                try:
                    self._get_access_token(force_refresh=True)
                    events = self._request_events(params, realm)
                except requests.RequestException as exc2:
                    logger.error(
                        "Fallo de autenticación contra Keycloak (revisar "
                        "KEYCLOAK_ADMIN_USER/PASSWORD/CLIENT_ID y realm admin)",
                        extra={"error": str(exc2)},
                    )
                    return []
            else:
                logger.error("Error HTTP consultando eventos", extra={"error": str(exc)})
                return []
        except requests.RequestException as exc:
            logger.error("Error de red consultando eventos", extra={"error": str(exc)})
            return []

        # Filtro temporal fino (la API filtra por día; refinamos por timestamp).
        if since:
            events = [e for e in events if e.time >= since]
        if until:
            events = [e for e in events if e.time <= until]
        events.sort(key=lambda e: e.time)
        return events

    def _request_events(
        self, params: dict[str, object], realm: str | None
    ) -> list[KeycloakEvent]:
        """Ejecuta la petición HTTP de eventos y normaliza la respuesta.

        Args:
            params: parámetros de query.
            realm: realm objetivo.

        Returns:
            Lista de ``KeycloakEvent``.
        """
        token = self._get_access_token()
        headers = {"Authorization": f"Bearer {token}"}
        # verify=False: certificados self-signed del entorno de investigación.
        resp = requests.get(
            self.settings.events_endpoint(realm),
            headers=headers,
            params=params,
            verify=self.settings.tls_verify,
            timeout=self.settings.http_timeout_seconds,
        )
        resp.raise_for_status()
        return [KeycloakEvent.from_admin_api(item) for item in resp.json()]

    def get_recent_events(
        self, event_types: list[str] | None, window_minutes: int
    ) -> list[KeycloakEvent]:
        """Devuelve los eventos de los últimos ``window_minutes`` minutos.

        Args:
            event_types: tipos a filtrar.
            window_minutes: tamaño de la ventana temporal en minutos.

        Returns:
            Lista de eventos dentro de la ventana.
        """
        from datetime import timedelta

        now = datetime.now(timezone.utc)
        since = now - timedelta(minutes=window_minutes)
        # Sin límite superior (until=None): evita que un pequeño desfase de reloj
        # entre el agente y los timestamps de Keycloak descarte los eventos más
        # recientes (los eventos no pueden ser del futuro, así que no hace falta).
        return self.get_events(event_types=event_types, since=since, until=None)

    def get_events_config(self, realm: str | None = None) -> dict | None:
        """Consulta la configuración de eventos de un realm.

        Args:
            realm: realm a consultar; por defecto el configurado.

        Returns:
            El JSON de ``/events/config`` (con ``eventsEnabled`` y
            ``enabledEventTypes``), o ``None`` ante un error.
        """
        target = realm or self.settings.keycloak_realm
        url = (
            f"{self.settings.keycloak_base_url}/admin/realms/{target}/events/config"
        )
        try:
            token = self._get_access_token()
            # verify=False: certificados self-signed del entorno de investigación.
            resp = requests.get(
                url,
                headers={"Authorization": f"Bearer {token}"},
                verify=self.settings.tls_verify,
                timeout=self.settings.http_timeout_seconds,
            )
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as exc:
            logger.error(
                "No se pudo leer la config de eventos", extra={"error": str(exc)}
            )
            return None

    def self_check(self) -> None:
        """Diagnóstico de arranque de la conectividad de eventos.

        Loguea si los eventos están habilitados en el realm y cuántos hay en la
        ventana. Si el guardado está apagado, lo advierte explícitamente: es la
        causa más común de que el agente "no detecte nada" en la capa OIDC.
        """
        config = self.get_events_config()
        if config is None:
            logger.warning(
                "Self-check: no se pudo leer la config de eventos "
                "(revisar credenciales admin, realm y conectividad)"
            )
            return

        enabled = config.get("eventsEnabled")
        types = config.get("enabledEventTypes") or []
        # Ventana operativa (la que usa la detección) vs. ventana diagnóstica
        # amplia (24h): permite distinguir "no hay eventos" de "hay eventos pero
        # fuera de la ventana de 5 min".
        op_window = self.settings.event_window_minutes
        in_op_window = self.get_recent_events(None, op_window)
        in_24h = self.get_recent_events(None, 24 * 60)
        logger.info(
            "Self-check de eventos Keycloak",
            extra={
                "realm": self.settings.keycloak_realm,
                "events_enabled": enabled,
                "enabled_event_types": types,
                "events_in_operational_window": len(in_op_window),
                "operational_window_minutes": op_window,
                "events_last_24h": len(in_24h),
            },
        )
        if enabled and not in_24h:
            logger.warning(
                "Self-check: eventsEnabled=true pero 0 eventos en 24h. Revisá que "
                "el ataque genere LOGIN/CODE_TO_TOKEN en este realm y que el admin "
                "tenga permiso view-events."
            )
        if not enabled:
            logger.warning(
                "Self-check: eventsEnabled=false en el realm; el agente NO "
                "recibirá eventos OIDC (CVE-2023-0264 indetectable). Activá "
                "'Save events' en Realm Settings -> Events y reintentá el ataque."
            )
