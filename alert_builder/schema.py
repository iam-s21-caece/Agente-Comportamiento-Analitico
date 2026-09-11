"""Esquema Pydantic de la alerta estructurada.

Implementado tal como lo propone el prompt de tesis (decisión confirmada con el
investigador). Es el entregable principal del agente: una alerta analítica que
identifica cada ataque y lo vincula con el componente arquitectural afectado.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field

Severity = Literal["info", "low", "medium", "high", "critical"]


class AffectedComponent(BaseModel):
    """Componente arquitectural afectado por una CVE detectada."""

    layer: Literal["application", "infrastructure"]
    stack: list[str] = Field(default_factory=list)
    specific_module: str = ""


class Evidence(BaseModel):
    """Una pieza de evidencia que respalda la detección."""

    source: str = Field(description="Origen: host_metrics, keycloak_events, check, ...")
    kind: str = Field(description="volumetric | correlational | other")
    description: str = ""
    data: dict[str, Any] = Field(default_factory=dict)


class DetectedCVE(BaseModel):
    """Una CVE detectada dentro de una alerta."""

    cve_id: str
    confidence: float = Field(ge=0.0, le=1.0)
    affected_component: AffectedComponent
    evidence: list[Evidence] = Field(default_factory=list)
    narrative: str = Field(default="", description="Explicación generada por el LLM.")


class AgentMetrics(BaseModel):
    """Métricas observacionales que el AGENTE estampa sobre la alerta (no el LLM).

    Se miden internamente: el tiempo de respuesta cuenta desde que el check
    determinista identifica la huella hasta que la alerta se emite, y el consumo
    corresponde al análisis ReAct. Alimentan el panel de parámetros en vivo del
    dashboard (se actualizan con cada alerta nueva). Son opcionales: valen ``None``
    si el análisis fue determinista (sin LLM) o no se pudo medir.
    """

    response_time_s: float | None = None
    tokens: int | None = None
    cost_usd: float | None = None


class Alert(BaseModel):
    """Alerta analítica estructurada emitida por el agente."""

    alert_id: str = Field(default_factory=lambda: f"alert-{uuid.uuid4().hex[:12]}")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    severity: Severity = "info"
    detected_cves: list[DetectedCVE] = Field(default_factory=list)
    chained: bool = Field(
        default=False, description="¿Hay encadenamiento entre las CVEs detectadas?"
    )
    summary: str = Field(default="", description="Narrativa global generada por el LLM.")
    # Observabilidad estampada por el agente (no por el LLM); ver AgentMetrics.
    metrics: AgentMetrics = Field(default_factory=AgentMetrics)
