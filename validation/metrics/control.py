"""Métricas de la dimensión CONTROL.

Miden que el agente haga lo que debe y no haga lo que no debe, de forma
predecible: que termine, que falle con gracia, que respete el presupuesto y no
crashee. Todas son reproducibles a partir de los ``ScenarioResult`` de una
campaña.
"""

from __future__ import annotations

from pydantic import BaseModel

from validation.scenario_runner import ScenarioResult


class ControlMetrics(BaseModel):
    """Resultados de la dimensión Control."""

    termination_rate: float = 0.0
    graceful_failure_rate: float = 0.0
    budget_adherence: float = 0.0
    timeout_rate: float = 0.0
    crash_rate: float = 0.0
    total_scenarios: int = 0
    # Economía de la invocación al LLM (habilitada por el consumo de tokens que
    # ahora persiste la traza): total de tokens y costo estimado de la campaña.
    total_tokens: int = 0
    estimated_cost_usd: float = 0.0


def compute_control(results: list[ScenarioResult]) -> ControlMetrics:
    """Calcula las métricas de Control de una campaña.

    Args:
        results: resultados de los escenarios ejecutados.

    Returns:
        ControlMetrics agregadas.
    """
    n = len(results)
    if n == 0:
        return ControlMetrics()

    terminated = sum(1 for r in results if r.terminated_ok)
    crashed = sum(1 for r in results if r.crashed)
    timed_out = sum(1 for r in results if r.timed_out)

    # graceful_failure_rate: de los fallos (crash o timeout), cuántos NO fueron
    # crash (es decir, fallaron de forma controlada).
    failures = crashed + timed_out
    graceful = timed_out  # timeout es un fallo controlado; crash no lo es
    graceful_failure_rate = (graceful / failures) if failures else 1.0

    # budget_adherence: tokens consumidos / tokens presupuestados (agregado).
    total_tokens = sum(r.tokens_used for r in results)
    total_budget = sum(r.token_budget for r in results)
    budget_adherence = (total_tokens / total_budget) if total_budget else 0.0
    total_cost = sum(r.estimated_cost_usd for r in results)

    return ControlMetrics(
        termination_rate=round(terminated / n, 3),
        graceful_failure_rate=round(graceful_failure_rate, 3),
        budget_adherence=round(budget_adherence, 3),
        timeout_rate=round(timed_out / n, 3),
        crash_rate=round(crashed / n, 3),
        total_scenarios=n,
        total_tokens=total_tokens,
        estimated_cost_usd=round(total_cost, 6),
    )
