"""Construcción y validación de alertas estructuradas.

El LLM, vía la tool ``emit_alert``, produce un dict; este módulo lo valida contra
el esquema Pydantic y deriva la severidad agregada. También ofrece un helper para
construir una alerta "determinista" (sin LLM) a partir de los CheckResult, útil
como fallback y para tests.
"""

from __future__ import annotations

from typing import Any

from config.logging_config import get_logger
from deterministic_checks.base import CheckResult
from knowledge_base.loader import KnowledgeBase

from .schema import AffectedComponent, Alert, DetectedCVE, Evidence

logger = get_logger(__name__)

# Orden de severidades para poder agregar (tomar la máxima).
_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def max_severity(severities: list[str]) -> str:
    """Devuelve la severidad más alta de una lista.

    Args:
        severities: lista de severidades.

    Returns:
        La severidad de mayor rango, o ``"info"`` si la lista está vacía.
    """
    valid = [s for s in severities if s in _SEVERITY_ORDER]
    if not valid:
        return "info"
    return max(valid, key=_SEVERITY_ORDER.index)


class AlertBuilder:
    """Valida y normaliza alertas provenientes del LLM o de los checks."""

    def __init__(self, knowledge_base: KnowledgeBase) -> None:
        """Inicializa el builder.

        Args:
            knowledge_base: base de conocimiento para completar componentes.
        """
        self.kb = knowledge_base

    def from_llm_dict(self, payload: dict[str, Any]) -> Alert:
        """Valida un dict emitido por el LLM y lo convierte en ``Alert``.

        Si el ``affected_component`` viene incompleto, se completa desde la base
        de conocimiento usando el ``cve_id``.

        Args:
            payload: dict producido por la tool ``emit_alert``.

        Returns:
            Alert validada.

        Raises:
            pydantic.ValidationError: si el payload es estructuralmente inválido.
        """
        enriched = dict(payload)
        for cve in enriched.get("detected_cves", []):
            if not cve.get("affected_component"):
                definition = self.kb.get(cve.get("cve_id", ""))
                if definition:
                    cve["affected_component"] = definition.affected_component.model_dump()
        alert = Alert.model_validate(enriched)

        # Severidad agregada coherente con las CVEs detectadas.
        if alert.detected_cves and alert.severity == "info":
            sevs = []
            for cve in alert.detected_cves:
                definition = self.kb.get(cve.cve_id)
                sevs.append(definition.severity if definition else "medium")
            alert.severity = max_severity(sevs)
        return alert

    def from_check_results(self, results: list[CheckResult]) -> Alert:
        """Construye una alerta determinista a partir de CheckResult.

        Fallback sin LLM: arma la alerta directamente desde los checks que
        dispararon. Útil para evaluación reproducible y tests.

        Args:
            results: resultados de los checks deterministas.

        Returns:
            Alert con las CVEs cuyos checks dispararon.
        """
        detected: list[DetectedCVE] = []
        severities: list[str] = []
        for result in results:
            if not result.triggered:
                continue
            definition = self.kb.get(result.cve_id)
            component = (
                AffectedComponent(**definition.affected_component.model_dump())
                if definition
                else AffectedComponent(layer="application")
            )
            kind = (
                "volumetric"
                if definition and definition.evidence_type == "volumetric_metrics"
                else "correlational"
            )
            detected.append(
                DetectedCVE(
                    cve_id=result.cve_id,
                    confidence=result.score,
                    affected_component=component,
                    evidence=[
                        Evidence(
                            source=result.check_id,
                            kind=kind,
                            description=result.message,
                            data=result.evidence,
                        )
                    ],
                    narrative=result.message,
                )
            )
            severities.append(result.severity)

        return Alert(
            severity=max_severity(severities),
            detected_cves=detected,
            chained=len(detected) > 1,
            summary=(
                "Alerta determinista generada desde checks (sin narrativa LLM)."
                if detected
                else "Sin detecciones en los checks deterministas."
            ),
        )
