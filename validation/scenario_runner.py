"""Ejecución de escenarios de validación end-to-end.

Un escenario se ejecuta así:
  1. setup.sh (opcional)
  2. marcar t0
  3. execute.sh (opcional) — dispara el escenario (lo aprueba/ejecuta el investigador)
  4. recolectar alertas del agente durante la ventana [t0, t0 + post_window]
  5. teardown.sh (opcional)
  6. comparar salida real vs expected → ScenarioResult

Las dependencias externas (ejecutar scripts, obtener alertas) se inyectan para
poder testear la lógica de comparación sin VPS ni Keycloak.
"""

from __future__ import annotations

import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Protocol

from pydantic import BaseModel, Field

from config.logging_config import get_logger

from .ground_truth import (
    ExpectedOutput,
    ScenarioSpec,
    load_expected,
    load_scenario_spec,
)

logger = get_logger(__name__)

# Umbral de confianza a partir del cual se considera una identificación "firme".
HIGH_CONFIDENCE = 0.6

# Proveedor de alertas: dado un rango temporal, devuelve las alertas (dicts)
# emitidas por el agente en ese rango.
AlertProvider = Callable[[datetime, datetime], list[dict[str, Any]]]


class ScenarioResult(BaseModel):
    """Resultado de ejecutar y evaluar un escenario."""

    scenario_id: str
    scenario_type: str
    expected: ExpectedOutput
    alerts: list[dict[str, Any]] = Field(default_factory=list)

    # Comparación
    passed: bool = False
    partial: bool = False
    mismatches: list[str] = Field(default_factory=list)

    # Señales de control
    terminated_ok: bool = True
    crashed: bool = False
    timed_out: bool = False
    tokens_used: int = 0
    token_budget: int = 0

    # Correlación con trazabilidad y rúbrica
    analysis_ids: list[str] = Field(default_factory=list)
    rubric_scores: dict[str, float] = Field(default_factory=dict)

    # -------- helpers derivados de las alertas --------
    def detected_cves(self) -> set[str]:
        """CVE-IDs detectados en las alertas del escenario."""
        out: set[str] = set()
        for alert in self.alerts:
            for cve in alert.get("detected_cves", []):
                if cve.get("cve_id"):
                    out.add(cve["cve_id"].upper())
        return out

    def alerted(self) -> bool:
        """``True`` si el agente emitió alguna alerta con contenido."""
        return any(
            a.get("detected_cves") or a.get("severity", "info") != "info"
            for a in self.alerts
        )

    def max_confidence(self) -> float:
        """Máxima confianza entre todas las CVEs detectadas."""
        confs = [
            cve.get("confidence", 0.0)
            for a in self.alerts
            for cve in a.get("detected_cves", [])
        ]
        return max(confs, default=0.0)

    def component_layer_for(self, cve_id: str) -> str | None:
        """Devuelve la capa arquitectural que el agente asignó a una CVE."""
        for a in self.alerts:
            for cve in a.get("detected_cves", []):
                if (cve.get("cve_id") or "").upper() == cve_id.upper():
                    comp = cve.get("affected_component") or {}
                    return comp.get("layer")
        return None


def compare(expected: ExpectedOutput, result: ScenarioResult) -> ScenarioResult:
    """Compara la salida real del agente contra el ground truth.

    Aplica el criterio acordado para escenarios ambiguos: la respuesta correcta
    es EXPRESAR INCERTIDUMBRE sin encasillar en una CVE conocida con alta
    confianza (no un falso reconocimiento).

    Args:
        expected: ground truth del escenario.
        result: resultado con las alertas recolectadas (se completa in-place).

    Returns:
        El mismo ``result`` con ``passed``/``partial``/``mismatches`` seteados.
    """
    mismatches: list[str] = []
    eo = expected.expected_agent_output

    if expected.scenario_type == "ambiguous":
        # Correcto = no afirmar una CVE conocida con alta confianza.
        firm_known = any(
            cve.get("confidence", 0.0) >= HIGH_CONFIDENCE
            for a in result.alerts
            for cve in a.get("detected_cves", [])
        )
        if firm_known:
            mismatches.append(
                "Escenario ambiguo encasillado en CVE conocida con alta confianza "
                "(se esperaba incertidumbre)."
            )
        result.passed = not firm_known
        result.partial = False
        result.mismatches = mismatches
        return result

    # Positivos / negativos.
    if eo.should_alert and not result.alerted():
        mismatches.append("Se esperaba alerta y el agente no alertó.")
    if not eo.should_alert and result.alerted():
        mismatches.append("No se esperaba alerta y el agente alertó (falso positivo).")

    expected_cves = expected.expected_cves
    detected = result.detected_cves()
    missing = expected_cves - detected
    extra = detected - expected_cves
    if missing:
        mismatches.append(f"CVEs esperadas no detectadas: {sorted(missing)}.")
    if extra:
        mismatches.append(f"CVEs detectadas no esperadas: {sorted(extra)}.")

    # Confianza dentro del rango esperado (± tolerancia) para positivos.
    if eo.should_alert and expected_cves:
        lo, hi = (eo.expected_confidence_range + [0.0, 1.0])[:2]
        delta = expected.tolerance.confidence_delta
        conf = result.max_confidence()
        if not (lo - delta <= conf <= hi + delta):
            mismatches.append(
                f"Confianza {conf:.2f} fuera del rango esperado "
                f"[{lo}, {hi}] (±{delta})."
            )

    # Componente arquitectural.
    for cve_id in sorted(expected_cves & detected):
        layer = result.component_layer_for(cve_id)
        if eo.should_link_component and layer not in eo.should_link_component:
            mismatches.append(
                f"Componente incorrecto para {cve_id}: '{layer}' no está en "
                f"{eo.should_link_component}."
            )

    result.mismatches = mismatches
    # Pasa si no hay mismatches; parcial si detectó algo esperado pero con fallas.
    result.passed = len(mismatches) == 0
    result.partial = (not result.passed) and bool(expected_cves & detected)
    return result


def run_scenario(
    scenario_dir: Path,
    alert_provider: AlertProvider,
    run_script: Callable[[Path], None] | None = None,
    now_fn: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    token_budget: int = 0,
) -> ScenarioResult:
    """Ejecuta un escenario completo y devuelve su resultado evaluado.

    Args:
        scenario_dir: directorio del escenario (con scenario.yaml/expected.yaml).
        alert_provider: callable que devuelve alertas en un rango temporal.
        run_script: ejecutor de scripts (inyectable). Si ``None`` usa subprocess.
        now_fn: proveedor de tiempo (inyectable para tests).
        token_budget: presupuesto de tokens para este escenario (control).

    Returns:
        ScenarioResult evaluado.
    """
    spec = load_scenario_spec(scenario_dir / "scenario.yaml")
    expected = load_expected(scenario_dir / "expected.yaml")
    runner = run_script or (lambda p: _default_run_script(p))

    result = ScenarioResult(
        scenario_id=spec.scenario_id,
        scenario_type=spec.scenario_type,
        expected=expected,
        token_budget=token_budget,
    )

    try:
        if spec.setup:
            runner(scenario_dir / spec.setup)

        t0 = now_fn()
        if spec.execute:
            runner(scenario_dir / spec.execute)

        window_end = t0 + timedelta(seconds=spec.post_window_seconds)
        result.alerts = alert_provider(t0, window_end)

        if spec.teardown:
            runner(scenario_dir / spec.teardown)
    except subprocess.SubprocessError as exc:
        logger.error("Fallo ejecutando script del escenario", extra={"error": str(exc)})
        result.crashed = True

    return compare(expected, result)


def _default_run_script(path: Path) -> None:
    """Ejecuta un script del escenario con bash (uso real en la VPS).

    Args:
        path: ruta al script a ejecutar.
    """
    if not path.exists():
        logger.warning("Script de escenario inexistente", extra={"path": str(path)})
        return
    subprocess.run(["bash", str(path)], check=True, timeout=600)


class ScenarioRunnerProtocol(Protocol):
    """Contrato mínimo para runners de escenario (facilita el mockeo)."""

    def __call__(self, scenario_dir: Path) -> ScenarioResult:  # pragma: no cover
        ...
