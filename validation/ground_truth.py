"""Ground truth extendido para la validación de escenarios.

Define y carga los dos artefactos que describen un escenario de validación:

  * ``scenario.yaml``  → qué es el escenario y cómo se ejecuta.
  * ``expected.yaml``  → qué debería concluir el agente (la "verdad").

Sobre estos artefactos se apoya toda la evaluación de las tres dimensiones de
Russell & Norvig (control, autonomía, knowledge).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field

from config.logging_config import get_logger

logger = get_logger(__name__)

ScenarioType = Literal["positive", "negative", "ambiguous"]


class ScenarioSpec(BaseModel):
    """Descripción de un escenario (``scenario.yaml``)."""

    scenario_id: str
    scenario_type: ScenarioType
    description: str = ""
    # Scripts opcionales relativos al directorio del escenario.
    setup: str | None = None
    execute: str | None = None
    teardown: str | None = None
    # Ventana de observación posterior a execute (segundos).
    post_window_seconds: int = 60


class AttackPresent(BaseModel):
    """Un ataque presente en el escenario (o ninguno, en negativos)."""

    cve_id: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    timestamp_range: list[str] = Field(default_factory=list)


class ExpectedAgentOutput(BaseModel):
    """Lo que se espera que el agente concluya."""

    should_alert: bool
    should_identify_cves: list[str] = Field(default_factory=list)
    should_link_component: list[str] = Field(default_factory=list)
    expected_confidence_range: list[float] = Field(default_factory=lambda: [0.0, 1.0])
    # Para escenarios ambiguos: se acepta (y se espera) incertidumbre.
    acceptable_uncertainty: bool = False


class Tolerance(BaseModel):
    """Tolerancias para la comparación agente vs esperado."""

    timing_seconds: int = 30
    confidence_delta: float = 0.15


class ExpectedOutput(BaseModel):
    """Ground truth de un escenario (``expected.yaml``)."""

    scenario_id: str
    scenario_type: ScenarioType
    attacks_present: list[AttackPresent] = Field(default_factory=list)
    expected_agent_output: ExpectedAgentOutput
    tolerance: Tolerance = Field(default_factory=Tolerance)

    @property
    def expected_cves(self) -> set[str]:
        """CVE-IDs esperados (en mayúsculas)."""
        return {c.upper() for c in self.expected_agent_output.should_identify_cves}


def load_scenario_spec(path: Path) -> ScenarioSpec:
    """Carga y valida un ``scenario.yaml``.

    Args:
        path: ruta al archivo.

    Returns:
        ScenarioSpec validado.
    """
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    return ScenarioSpec.model_validate(data)


def load_expected(path: Path) -> ExpectedOutput:
    """Carga y valida un ``expected.yaml``.

    Args:
        path: ruta al archivo.

    Returns:
        ExpectedOutput validado.
    """
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    return ExpectedOutput.model_validate(data)


def discover_scenarios(scenarios_dir: Path, scenario_type: str | None = None) -> list[Path]:
    """Descubre directorios de escenario bajo ``scenarios_dir``.

    Un directorio es un escenario si contiene ``scenario.yaml``.

    Args:
        scenarios_dir: raíz de escenarios (con subcarpetas positive/negative/ambiguous).
        scenario_type: si se da, filtra por ese tipo (subcarpeta).

    Returns:
        Lista de rutas a directorios de escenario, ordenada.
    """
    root = Path(scenarios_dir)
    if not root.exists():
        return []
    subdirs = [root / scenario_type] if scenario_type else [
        root / t for t in ("positive", "negative", "ambiguous")
    ]
    found: list[Path] = []
    for sub in subdirs:
        if not sub.is_dir():
            continue
        for child in sorted(sub.iterdir()):
            if (child / "scenario.yaml").exists():
                found.append(child)
    return found
