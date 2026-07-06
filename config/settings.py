"""Configuración central del agente.

Toda la configuración se resuelve desde variables de entorno (cargadas desde
``.env``) usando ``pydantic-settings``. No se hardcodean secretos: la API key de
DeepSeek y las credenciales de Keycloak viven exclusivamente en el entorno.

Las rutas por defecto apuntan al layout de la VPS de investigación
(``/root/keycloak/...``) descripto en el prompt de tesis, pero todas son
sobreescribibles por entorno para poder ejecutar el agente en otros equipos.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Directorio raíz del paquete del agente (……/agente).
AGENT_PACKAGE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    """Configuración tipada del agente.

    Attributes:
        deepseek_api_key: API key de DeepSeek (obligatoria para el modo LLM).
        keycloak_realm: Realm a monitorear para eventos OIDC (decisión: ``poc``).
        tls_verify: Verificación TLS hacia Keycloak. Forzado a ``False`` por los
            certificados self-signed del entorno de investigación.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ----- LLM (DeepSeek) -------------------------------------------------
    deepseek_api_key: str = Field(default="", description="API key de DeepSeek.")
    deepseek_base_url: str = Field(default="https://api.deepseek.com")
    deepseek_model: str = Field(default="deepseek-chat")
    llm_temperature: float = Field(default=0.1)
    llm_timeout_seconds: int = Field(default=120)

    # ----- Keycloak / Admin REST API -------------------------------------
    keycloak_base_url: str = Field(default="https://localhost:8443")
    # Decisión del investigador: el realm monitoreado es "poc".
    keycloak_realm: str = Field(default="poc")
    keycloak_admin_realm: str = Field(default="master")
    keycloak_admin_user: str = Field(default="admin")
    keycloak_admin_password: str = Field(default="")
    keycloak_admin_client_id: str = Field(default="admin-cli")
    # Los certificados son self-signed: NO se debe usar verify=True.
    tls_verify: bool = Field(default=False)
    http_timeout_seconds: int = Field(default=15)

    # ----- Docker / contenedor -------------------------------------------
    container_name: str = Field(default="keycloak")

    # ----- Fallback H2 ----------------------------------------------------
    h2_jdbc_url: str = Field(
        default="jdbc:h2:file:/opt/keycloak/data/h2/keycloakdb;AUTO_SERVER=TRUE"
    )
    h2_user: str = Field(default="sa")
    h2_password: str = Field(default="password")
    h2_jar_glob: str = Field(
        default="/opt/keycloak/lib/lib/main/com.h2database.h2-*.jar"
    )

    # ----- Detección del proceso JVM -------------------------------------
    # Substring buscado en el cmdline para localizar la JVM de Keycloak.
    jvm_cmdline_match: str = Field(default="kc.config")

    # ----- Baseline DoS (modo híbrido) -----------------------------------
    # Si el archivo existe se lee; si no, se calcula al iniciar y se persiste.
    baseline_path: Path = Field(
        default=AGENT_PACKAGE_DIR / "config" / "baseline.json"
    )
    baseline_warmup_seconds: int = Field(default=20)
    baseline_sample_interval_seconds: float = Field(default=2.0)

    # ----- Ventanas y bucle ----------------------------------------------
    event_window_minutes: int = Field(default=5)
    continuous_interval_seconds: int = Field(default=10)
    # Si es True, el ReAct se ejecuta en cada ciclo; si es False, solo cuando un
    # check determinista dispara (control de costo de tokens).
    always_analyze: bool = Field(default=False)
    # Cooldown de alertas: no re-analizar/re-alertar la misma anomalía dentro de
    # esta ventana (segundos). Evita spam y gasto de tokens en ataques que
    # persisten en la ventana de eventos. Una anomalía nueva dispara igual.
    alert_cooldown_seconds: int = Field(default=300)

    # ----- ReAct ----------------------------------------------------------
    react_max_iterations: int = Field(default=20)

    # ----- Salida de alertas ---------------------------------------------
    # Directorio donde se persisten las alertas (montado como volumen en la VPS).
    alerts_dir: Path = Field(default=AGENT_PACKAGE_DIR / "alerts")

    # ----- Dashboard embebido --------------------------------------------
    # El agente sirve el dashboard y expone alerts.jsonl bajo la misma URL, así
    # no hace falta montar un http.server aparte ni pelear con rutas relativas.
    dashboard_enabled: bool = Field(default=True)
    dashboard_host: str = Field(default="0.0.0.0")
    dashboard_port: int = Field(default=8081)
    dashboard_dir: Path = Field(default=AGENT_PACKAGE_DIR / "dashboard")

    # ----- Trazabilidad ---------------------------------------------------
    # Capa observacional del ciclo agéntico (no altera la lógica del agente).
    trace_enabled: bool = Field(default=True)
    traces_dir: Path = Field(default=AGENT_PACKAGE_DIR / "data" / "traces")
    # Tope de tamaño por evento: los strings más largos se truncan (decisión:
    # "completo pero con límite"). Evita trazas gigantes por chain-of-thought.
    trace_max_event_bytes: int = Field(default=8192)

    # ----- Knowledge base ------------------------------------------------
    cves_dir: Path = Field(default=AGENT_PACKAGE_DIR / "knowledge_base" / "cves")

    # ----- Validación (campañas, escenarios, reportes) -------------------
    scenarios_dir: Path = Field(default=AGENT_PACKAGE_DIR / "validation" / "scenarios")
    validation_reports_dir: Path = Field(
        default=AGENT_PACKAGE_DIR / "data" / "validation" / "reports"
    )
    rubrics_dir: Path = Field(
        default=AGENT_PACKAGE_DIR / "data" / "validation" / "rubrics"
    )
    knowledge_consistency_path: Path = Field(
        default=AGENT_PACKAGE_DIR / "validation" / "knowledge_consistency.yaml"
    )
    # Presupuesto de tokens por campaña (decisión: 500k). Corta con warning.
    validation_token_budget: int = Field(default=500_000)

    # ----- Logging --------------------------------------------------------
    log_level: str = Field(default="INFO")
    log_format: Literal["json", "plain"] = Field(default="json")

    @property
    def token_endpoint(self) -> str:
        """URL del endpoint de token del realm administrativo."""
        return (
            f"{self.keycloak_base_url}/realms/{self.keycloak_admin_realm}"
            "/protocol/openid-connect/token"
        )

    def events_endpoint(self, realm: str | None = None) -> str:
        """URL del endpoint de eventos para el realm dado (o el configurado)."""
        target = realm or self.keycloak_realm
        return f"{self.keycloak_base_url}/admin/realms/{target}/events"


@lru_cache
def get_settings() -> Settings:
    """Devuelve la instancia de configuración (cacheada).

    Returns:
        Settings: configuración resuelta desde el entorno.
    """
    return Settings()
