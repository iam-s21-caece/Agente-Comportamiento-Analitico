"""Métricas de la dimensión AUTONOMÍA.

Miden que las decisiones autónomas del agente sean correctas verificablemente:
precisión/recall/F1 de detección, identificación correcta de CVE, vínculo
arquitectural correcto y coherencia del razonamiento (rúbrica).
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from knowledge_base.loader import KnowledgeBase
from validation.scenario_runner import ScenarioResult


class DetectionCounts(BaseModel):
    """Conteos TP/FP/FN para una CVE o el global."""

    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        """Precisión = TP / (TP + FP)."""
        denom = self.tp + self.fp
        return round(self.tp / denom, 3) if denom else 0.0

    @property
    def recall(self) -> float:
        """Recall = TP / (TP + FN)."""
        denom = self.tp + self.fn
        return round(self.tp / denom, 3) if denom else 0.0

    @property
    def f1(self) -> float:
        """F1 = 2PR / (P + R)."""
        p, r = self.precision, self.recall
        return round(2 * p * r / (p + r), 3) if (p + r) else 0.0


class AutonomyMetrics(BaseModel):
    """Resultados de la dimensión Autonomía."""

    global_counts: DetectionCounts = Field(default_factory=DetectionCounts)
    per_cve: dict[str, DetectionCounts] = Field(default_factory=dict)
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    identification_accuracy: float = 0.0
    component_linking_accuracy: float = 0.0
    reasoning_coherence_score: float | None = None


def compute_autonomy(
    results: list[ScenarioResult], knowledge_base: KnowledgeBase
) -> AutonomyMetrics:
    """Calcula las métricas de Autonomía de una campaña.

    Args:
        results: resultados de los escenarios.
        knowledge_base: base de conocimiento (capa esperada por CVE).

    Returns:
        AutonomyMetrics agregadas.
    """
    global_counts = DetectionCounts()
    per_cve: dict[str, DetectionCounts] = {}

    alerts_with_correct_cve = 0
    total_alerts = 0
    component_correct = 0
    component_total = 0

    for result in results:
        expected = result.expected.expected_cves
        detected = result.detected_cves()

        for cve_id in expected | detected:
            counts = per_cve.setdefault(cve_id, DetectionCounts())
            if cve_id in expected and cve_id in detected:
                counts.tp += 1
                global_counts.tp += 1
            elif cve_id in detected:  # detectada pero no esperada
                counts.fp += 1
                global_counts.fp += 1
            else:  # esperada pero no detectada
                counts.fn += 1
                global_counts.fn += 1

        # identification_accuracy: por alerta emitida, ¿acertó alguna CVE esperada?
        for alert in result.alerts:
            cves = alert.get("detected_cves", [])
            if not cves:
                continue
            total_alerts += 1
            ids = {(c.get("cve_id") or "").upper() for c in cves}
            if ids & expected:
                alerts_with_correct_cve += 1

        # component_linking_accuracy sobre las CVEs correctamente detectadas.
        for cve_id in expected & detected:
            component_total += 1
            definition = knowledge_base.get(cve_id)
            expected_layer = (
                definition.affected_component.layer if definition else None
            )
            if result.component_layer_for(cve_id) == expected_layer:
                component_correct += 1

    # Coherencia del razonamiento: promedio del eje 'coherencia' de la rúbrica.
    coherence_scores = [
        r.rubric_scores["coherencia_logica"]
        for r in results
        if "coherencia_logica" in r.rubric_scores
    ]
    reasoning = (
        round(sum(coherence_scores) / len(coherence_scores), 3)
        if coherence_scores
        else None
    )

    return AutonomyMetrics(
        global_counts=global_counts,
        per_cve=per_cve,
        precision=global_counts.precision,
        recall=global_counts.recall,
        f1=global_counts.f1,
        identification_accuracy=(
            round(alerts_with_correct_cve / total_alerts, 3) if total_alerts else 0.0
        ),
        component_linking_accuracy=(
            round(component_correct / component_total, 3) if component_total else 0.0
        ),
        reasoning_coherence_score=reasoning,
    )
