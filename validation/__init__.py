"""Capa de validación y trazabilidad del agente (Russell & Norvig).

Valida empíricamente el agente en tres dimensiones —control, autonomía y
knowledge— mediante escenarios positivos/negativos/ambiguos, métricas
reproducibles y una rúbrica cualitativa auditable.
"""

from .ground_truth import (
    ExpectedOutput,
    ScenarioSpec,
    discover_scenarios,
    load_expected,
    load_scenario_spec,
)
from .scenario_runner import ScenarioResult, compare, run_scenario

__all__ = [
    "ExpectedOutput",
    "ScenarioSpec",
    "discover_scenarios",
    "load_expected",
    "load_scenario_spec",
    "ScenarioResult",
    "compare",
    "run_scenario",
]
