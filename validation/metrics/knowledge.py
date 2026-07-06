"""Métricas de la dimensión KNOWLEDGE.

Miden que la base de conocimiento del agente sea correcta, completa y aplicable:
cobertura de CVEs conocidas, generalización a variantes, rechazo apropiado ante
lo desconocido, y consistencia con advisories oficiales (cross-check manual).
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from config.logging_config import get_logger
from knowledge_base.loader import KnowledgeBase
from validation.scenario_runner import HIGH_CONFIDENCE, ScenarioResult

logger = get_logger(__name__)


class KnowledgeMetrics(BaseModel):
    """Resultados de la dimensión Knowledge."""

    coverage: float = 0.0
    generalization_rate: float = 0.0
    rejection_rate_on_unknown: float = 0.0
    false_recognition_rate: float = 0.0
    knowledge_consistency_score: float | None = None
    detectable_cves: list[str] = Field(default_factory=list)


def _is_unknown_attack(result: ScenarioResult) -> bool:
    """Heurística: escenario ambiguo de tipo 'unknown-attack'."""
    return result.scenario_type == "ambiguous" and "unknown" in result.scenario_id.lower()


def _is_variant(result: ScenarioResult) -> bool:
    """Heurística: escenario positivo de variante."""
    return result.scenario_type == "positive" and "variant" in result.scenario_id.lower()


def _firm_known_detection(result: ScenarioResult) -> bool:
    """``True`` si el agente afirmó una CVE conocida con alta confianza."""
    return any(
        cve.get("confidence", 0.0) >= HIGH_CONFIDENCE
        for a in result.alerts
        for cve in a.get("detected_cves", [])
    )


def compute_knowledge(
    results: list[ScenarioResult],
    knowledge_base: KnowledgeBase,
    consistency_record: Path | str | None = None,
) -> KnowledgeMetrics:
    """Calcula las métricas de Knowledge de una campaña.

    Args:
        results: resultados de los escenarios.
        knowledge_base: base de conocimiento del agente.
        consistency_record: ruta a un YAML con el cross-check manual contra
            advisories oficiales (``{cve_id: score_0_1}``). Sin red.

    Returns:
        KnowledgeMetrics agregadas.
    """
    known_cves = set(knowledge_base.cves.keys())

    # Cobertura: CVEs conocidas efectivamente detectadas en algún positivo.
    detected_in_positives: set[str] = set()
    for r in results:
        if r.scenario_type == "positive":
            detected_in_positives |= r.detected_cves() & known_cves
    coverage = len(detected_in_positives) / len(known_cves) if known_cves else 0.0

    # Generalización: variantes detectadas / variantes probadas.
    variants = [r for r in results if _is_variant(r)]
    variants_ok = sum(1 for r in variants if r.expected_cves & r.detected_cves())
    generalization = (variants_ok / len(variants)) if variants else 0.0

    # Rechazo / falso reconocimiento sobre 'unknown-attack'.
    unknowns = [r for r in results if _is_unknown_attack(r)]
    false_recognition = sum(1 for r in unknowns if _firm_known_detection(r))
    rejected = len(unknowns) - false_recognition
    rejection_rate = (rejected / len(unknowns)) if unknowns else 0.0
    false_recognition_rate = (false_recognition / len(unknowns)) if unknowns else 0.0

    return KnowledgeMetrics(
        coverage=round(coverage, 3),
        generalization_rate=round(generalization, 3),
        rejection_rate_on_unknown=round(rejection_rate, 3),
        false_recognition_rate=round(false_recognition_rate, 3),
        knowledge_consistency_score=_load_consistency(consistency_record),
        detectable_cves=sorted(detected_in_positives),
    )


def _load_consistency(path: Path | str | None) -> float | None:
    """Carga el cross-check manual y promedia los scores por CVE.

    Args:
        path: YAML ``{cve_id: score}`` con scores en [0, 1], o ``None``.

    Returns:
        Promedio de consistencia, o ``None`` si no hay registro.
    """
    if not path:
        return None
    p = Path(path)
    if not p.exists():
        logger.warning("Registro de consistencia inexistente", extra={"path": str(p)})
        return None
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        scores = [float(v) for v in data.values()]
        return round(sum(scores) / len(scores), 3) if scores else None
    except (yaml.YAMLError, ValueError) as exc:
        logger.error("Registro de consistencia inválido", extra={"error": str(exc)})
        return None
