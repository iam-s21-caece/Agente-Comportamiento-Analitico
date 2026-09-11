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
import time
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

# Proveedor de análisis (trazas): dado un rango temporal, devuelve un resumen por
# análisis {analysis_id, total_tokens, cost_usd} para las métricas de eficiencia.
TraceProvider = Callable[[datetime, datetime], list[dict[str, Any]]]


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

    # Eficiencia (métricas nuevas): costo del LLM y tiempo de respuesta por alerta.
    # Se pueblan desde la traza y las alertas; siguen siendo datos sobre el
    # ScenarioResult, de modo que las métricas continúan siendo funciones puras.
    estimated_cost_usd: float = 0.0
    response_times_s: list[float] = Field(default_factory=list)

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
    trace_provider: TraceProvider | None = None,
    observe_window: bool = False,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> ScenarioResult:
    """Ejecuta un escenario completo y devuelve su resultado evaluado.

    Args:
        scenario_dir: directorio del escenario (con scenario.yaml/expected.yaml).
        alert_provider: callable que devuelve alertas en un rango temporal.
        run_script: ejecutor de scripts (inyectable). Si ``None`` usa subprocess.
        now_fn: proveedor de tiempo (inyectable para tests).
        token_budget: presupuesto de tokens para este escenario (control).
        trace_provider: callable opcional que devuelve el resumen por análisis
            (tokens/costo) del rango, desde la traza. Si ``None``, esas métricas
            de eficiencia quedan en cero (p. ej. corridas ``--no-llm``).
        observe_window: si ``True`` (corrida real), ESPERA la ventana de
            observación antes de recolectar, para que el agente tenga tiempo de
            detectar y emitir la alerta durante la ventana. En ``False`` (tests)
            recolecta al instante.
        sleep_fn: función de espera (inyectable para tests).

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
        # En corridas reales, esperar la ventana: el agente detecta y alerta
        # durante ese lapso (ciclo + ReAct). Sin esta espera se recolectaría antes
        # de que la alerta exista y los positivos darían recall 0.
        if observe_window and spec.post_window_seconds > 0:
            logger.info(
                "Observando ventana del escenario",
                extra={"scenario_id": spec.scenario_id, "seconds": spec.post_window_seconds},
            )
            sleep_fn(spec.post_window_seconds)

        result.alerts = alert_provider(t0, window_end)
        # B (tiempo de respuesta): t0 (inicio del ataque) -> timestamp de la alerta.
        result.response_times_s = _response_times(result.alerts, t0)
        # A (tokens/costo): se leen de la traza para las alertas de esta ventana.
        if trace_provider is not None:
            summaries = trace_provider(t0, window_end)
            result.analysis_ids = [s["analysis_id"] for s in summaries if s.get("analysis_id")]
            result.tokens_used = sum(int(s.get("total_tokens", 0)) for s in summaries)
            result.estimated_cost_usd = round(
                sum(float(s.get("cost_usd", 0.0)) for s in summaries), 6
            )

        if spec.teardown:
            runner(scenario_dir / spec.teardown)
    except subprocess.SubprocessError as exc:
        logger.error("Fallo ejecutando script del escenario", extra={"error": str(exc)})
        result.crashed = True

    return compare(expected, result)


def _response_times(alerts: list[dict[str, Any]], t0: datetime) -> list[float]:
    """Calcula el tiempo de respuesta (s) de cada alerta desde t0 (inicio del ataque).

    Args:
        alerts: alertas de la ventana (con campo ``timestamp`` ISO-8601).
        t0: instante de inicio del ataque/escenario.

    Returns:
        Lista de latencias en segundos (una por alerta con timestamp válido).
    """
    out: list[float] = []
    for alert in alerts:
        raw = alert.get("timestamp")
        if not raw:
            continue
        try:
            ts = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        except ValueError:
            continue
        out.append(round((ts - t0).total_seconds(), 3))
    return out


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
