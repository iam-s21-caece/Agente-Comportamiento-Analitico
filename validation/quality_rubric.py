"""Rúbrica cualitativa para evaluar las narrativas del agente.

Cada alerta se evalúa por un humano en 5 ejes, escala 0-5 (decisión confirmada),
con justificación textual. El resultado se persiste para el análisis agregado y
alimenta ``reasoning_coherence_score`` en la dimensión Autonomía.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, Field, field_validator

# Los cinco ejes con su criterio explícito para el evaluador.
RUBRIC_AXES: dict[str, str] = {
    "correccion_tecnica": "Los hechos afirmados en la narrativa son verdaderos.",
    "coherencia_logica": "El razonamiento se sigue del análisis y la evidencia.",
    "completitud": "Cubre los aspectos relevantes del ataque detectado.",
    "precision_vinculo_arquitectural": "Identifica bien el componente afectado.",
    "claridad_expositiva": "La explicación es entendible y bien expresada.",
}

SCALE_MIN, SCALE_MAX = 0, 5


class RubricEvaluation(BaseModel):
    """Evaluación cualitativa de una alerta según la rúbrica."""

    alert_id: str
    analysis_id: str | None = None
    evaluator: str = "anon"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    scores: dict[str, int] = Field(default_factory=dict)
    justification: dict[str, str] = Field(default_factory=dict)

    @field_validator("scores")
    @classmethod
    def _validate_scores(cls, value: dict[str, int]) -> dict[str, int]:
        """Valida que los ejes y la escala 0-5 sean correctos."""
        for axis, score in value.items():
            if axis not in RUBRIC_AXES:
                raise ValueError(f"Eje desconocido: {axis}")
            if not (SCALE_MIN <= score <= SCALE_MAX):
                raise ValueError(f"Score fuera de escala 0-5: {axis}={score}")
        return value

    @property
    def average(self) -> float:
        """Promedio de los ejes puntuados."""
        return round(sum(self.scores.values()) / len(self.scores), 3) if self.scores else 0.0


def blank_evaluation(alert_id: str, analysis_id: str | None = None) -> RubricEvaluation:
    """Crea una evaluación vacía lista para completar.

    Args:
        alert_id: id de la alerta a evaluar.
        analysis_id: id del análisis (correlación con trazas).

    Returns:
        RubricEvaluation con los ejes sin puntuar.
    """
    return RubricEvaluation(alert_id=alert_id, analysis_id=analysis_id)


def save_evaluation(evaluation: RubricEvaluation, rubrics_dir: Path | str) -> Path:
    """Persiste una evaluación de rúbrica en disco.

    Args:
        evaluation: evaluación a guardar.
        rubrics_dir: directorio destino.

    Returns:
        Ruta del archivo escrito.
    """
    directory = Path(rubrics_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{evaluation.alert_id}.json"
    path.write_text(
        json.dumps(evaluation.model_dump(mode="json"), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return path


def aggregate(rubrics_dir: Path | str) -> dict[str, float]:
    """Promedia los scores por eje sobre todas las evaluaciones guardadas.

    Args:
        rubrics_dir: directorio con evaluaciones ``*.json``.

    Returns:
        Mapa eje -> promedio (incluye ``average_global``).
    """
    directory = Path(rubrics_dir)
    if not directory.exists():
        return {}
    sums: dict[str, float] = {axis: 0.0 for axis in RUBRIC_AXES}
    counts: dict[str, int] = {axis: 0 for axis in RUBRIC_AXES}
    for path in directory.glob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        for axis, score in (data.get("scores") or {}).items():
            if axis in sums:
                sums[axis] += score
                counts[axis] += 1
    result = {
        axis: round(sums[axis] / counts[axis], 3)
        for axis in RUBRIC_AXES
        if counts[axis]
    }
    if result:
        result["average_global"] = round(sum(result.values()) / len(result), 3)
    return result
