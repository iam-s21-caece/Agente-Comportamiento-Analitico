"""Check correlacional para CVE-2023-0264 (session hijacking via session_id reuse).

Implementa la lógica de detección del conocimiento de la CVE:

    Para cada evento CODE_TO_TOKEN (E):
        Buscar LOGIN event (L) donde L.session_id == E.session_id
        Si L existe y L.user_id != E.user_id:
            ANOMALÍA -> account takeover sobre L.user_id por parte de E.user_id

La evidencia es correlacional (relación entre eventos discretos), no volumétrica.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from config.logging_config import get_logger
from config.settings import Settings, get_settings
from knowledge_base.loader import CveDefinition
from signal_collector.base import KeycloakEvent

from .base import CheckBase, CheckResult

logger = get_logger(__name__)

CVE_ID = "CVE-2023-0264"


class OidcCorrelationCheck(CheckBase):
    """Detecta reutilización de ``session_id`` entre distintos usuarios."""

    check_id = "oidc_session_reuse"
    cve_id = CVE_ID

    def __init__(
        self,
        cve_def: CveDefinition,
        settings: Settings | None = None,
    ) -> None:
        """Inicializa el check.

        Args:
            cve_def: definición YAML de CVE-2023-0264.
            settings: configuración opcional.
        """
        self.cve_def = cve_def
        self.settings = settings or get_settings()

    def run(self, **kwargs: Any) -> list[CheckResult]:
        """Correlaciona LOGIN vs CODE_TO_TOKEN buscando reuse de session_id.

        Args:
            **kwargs: debe incluir ``events`` (list[KeycloakEvent]). Opcional
                ``window_minutes`` para acotar la ventana temporal.

        Returns:
            Lista con un ``CheckResult``. Si hay varias anomalías, todas se
            incluyen en la evidencia y el resultado se marca como disparado.
        """
        events: list[KeycloakEvent] = kwargs.get("events", []) or []
        window_minutes: int = int(
            kwargs.get("window_minutes", self.settings.event_window_minutes)
        )
        events = self._within_window(events, window_minutes)

        # Recorrido único en orden temporal manteniendo:
        #  - login_by_session: el LOGIN que originó cada session_id (dueño/víctima);
        #  - last_login: el LOGIN más reciente visto (el "actor" actual).
        anomalies: list[dict[str, Any]] = []
        login_by_session: dict[str, KeycloakEvent] = {}
        last_login: KeycloakEvent | None = None

        for ev in sorted(events, key=lambda e: e.time):
            if ev.type == "LOGIN" and ev.session_id:
                login_by_session[ev.session_id] = ev
                last_login = ev
                continue

            if ev.type != "CODE_TO_TOKEN" or not ev.session_id:
                continue

            owner = login_by_session.get(ev.session_id)  # login que creó la sesión
            victim = owner.user_id if owner else None
            anomaly: dict[str, Any] | None = None

            # FORMA 1 (spec original): el atacante figura como user del
            # CODE_TO_TOKEN sobre una sesión ajena.
            if owner and owner.user_id and ev.user_id and owner.user_id != ev.user_id:
                anomaly = {
                    "form": "user_mismatch",
                    "victim_user_id": owner.user_id,
                    "attacker_user_id": ev.user_id,
                    "victim_login_event": _evidence_event(owner),
                    "code_to_token_event": _evidence_event(ev),
                }

            # FORMA 2 (materialización real de CVE-2023-0264): el CODE_TO_TOKEN
            # reutiliza una sesión distinta de la del login más reciente, y ese
            # login es de otro usuario -> el actor secuestró la sesión ajena.
            # El token queda ligado a la víctima, por eso el user del evento es
            # la víctima; el atacante se ve en el login inmediatamente previo.
            elif (
                owner
                and last_login is not None
                and last_login.session_id != ev.session_id
                and victim
                and last_login.user_id
                and last_login.user_id != victim
            ):
                anomaly = {
                    "form": "session_reuse",
                    "victim_user_id": victim,
                    "attacker_user_id": last_login.user_id,
                    "attacker_login_event": _evidence_event(last_login),
                    "victim_login_event": _evidence_event(owner),
                    "code_to_token_event": _evidence_event(ev),
                }

            if anomaly:
                anomaly["session_id"] = ev.session_id
                # Compatibilidad: mantener también 'login_event'.
                anomaly.setdefault("login_event", anomaly.get("victim_login_event"))
                anomalies.append(anomaly)

        triggered = len(anomalies) > 0
        result = CheckResult(
            check_id=self.check_id,
            name="Correlación OIDC: reuse de session_id (account takeover)",
            cve_id=self.cve_id,
            triggered=triggered,
            severity=self.cve_def.severity if triggered else "info",
            score=1.0 if triggered else 0.0,
            message=(
                f"{len(anomalies)} reutilización(es) de session_id entre usuarios"
                if triggered
                else "Sin reuse anómalo de session_id en la ventana analizada"
            ),
            evidence={
                "anomalies": anomalies,
                "analyzed_events": len(events),
                "window_minutes": window_minutes,
            },
        )
        return [result]

    @staticmethod
    def _within_window(
        events: list[KeycloakEvent], window_minutes: int
    ) -> list[KeycloakEvent]:
        """Filtra eventos a la ventana temporal reciente.

        Args:
            events: eventos a filtrar.
            window_minutes: tamaño de la ventana en minutos.

        Returns:
            Eventos cuyo timestamp cae dentro de la ventana.
        """
        if not events:
            return []
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        return [e for e in events if e.time >= cutoff]


def _evidence_event(ev: KeycloakEvent) -> dict[str, Any]:
    """Reduce un evento a los campos relevantes para la evidencia.

    Args:
        ev: evento de Keycloak.

    Returns:
        Dict compacto con los campos de correlación.
    """
    return {
        "time": ev.time.isoformat(),
        "type": ev.type,
        "user_id": ev.user_id,
        "session_id": ev.session_id,
        "client_id": ev.client_id,
        "ip_address": ev.ip_address,
    }
