"""Métrica de TIEMPO DE RESPUESTA (latencia de detección).

Mide cuánto tarda el agente en emitir la alerta desde el inicio del ataque (t0).
Reutiliza los tiempos ya calculados por el runner (``ScenarioResult.response_times_s``,
derivados del t0 del escenario y del timestamp de cada alerta); acá solo se agregan
en estadísticos. Función pura sobre ``ScenarioResult``: mismos inputs, mismo resultado.
"""

from __future__ import annotations

import statistics

from pydantic import BaseModel

from validation.scenario_runner import ScenarioResult


class LatencyMetrics(BaseModel):
    """Estadísticos del tiempo de respuesta (segundos) de una campaña."""

    count: int = 0
    mean_s: float = 0.0
    p50_s: float = 0.0
    max_s: float = 0.0
    stdev_s: float = 0.0


def compute_latency(results: list[ScenarioResult]) -> LatencyMetrics:
    """Agrega los tiempos de respuesta de todas las alertas de la campaña.

    Args:
        results: resultados de los escenarios.

    Returns:
        LatencyMetrics con promedio, mediana, máximo y dispersión.
    """
    values = [t for r in results for t in r.response_times_s]
    if not values:
        return LatencyMetrics()
    return LatencyMetrics(
        count=len(values),
        mean_s=round(statistics.fmean(values), 3),
        p50_s=round(statistics.median(values), 3),
        max_s=round(max(values), 3),
        stdev_s=round(statistics.stdev(values), 3) if len(values) > 1 else 0.0,
    )
