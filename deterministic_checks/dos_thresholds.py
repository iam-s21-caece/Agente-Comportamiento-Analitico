"""Checks volumétricos para CVE-2026-33871 (CONTINUATION flood DoS).

Maneja el baseline en modo HÍBRIDO (decisión del investigador):
  * si existe ``baseline.json`` se lee;
  * si no, se calcula al iniciar capturando N segundos de estado normal y se
    persiste para runs futuros.

Los umbrales son RELATIVOS al baseline (factor) con un piso absoluto opcional,
tal como exige el conocimiento de la CVE (los valores absolutos varían entre
runs y no deben hardcodearse).
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from config.logging_config import get_logger
from config.settings import Settings, get_settings
from knowledge_base.loader import CveDefinition
from signal_collector.base import HostMetricsSnapshot
from signal_collector.host_metrics import HostMetricsCollector

from .base import CheckBase, CheckResult

logger = get_logger(__name__)

CVE_ID = "CVE-2026-33871"


class Baseline:
    """Baseline de métricas de estado normal."""

    def __init__(self, values: dict[str, float]) -> None:
        """Inicializa el baseline.

        Args:
            values: mapa métrica -> valor promedio en estado normal.
        """
        self.values = values

    def get(self, metric: str, default: float = 0.0) -> float:
        """Devuelve el valor baseline de una métrica."""
        return self.values.get(metric, default)

    def to_json(self) -> dict[str, Any]:
        """Serializa el baseline a dict JSON-friendly."""
        return {"values": self.values}

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "Baseline":
        """Reconstruye un baseline desde su dict serializado."""
        return cls(values=data.get("values", {}))


class BaselineManager:
    """Carga, calcula y persiste el baseline de métricas (modo híbrido)."""

    def __init__(
        self,
        settings: Settings | None = None,
        collector: HostMetricsCollector | None = None,
    ) -> None:
        """Inicializa el manager.

        Args:
            settings: configuración; si se omite se usa la global.
            collector: colector de host; si se omite se crea uno.
        """
        self.settings = settings or get_settings()
        self.collector = collector or HostMetricsCollector(self.settings)

    def load_or_build(self) -> Baseline:
        """Carga el baseline de archivo o lo calcula y persiste.

        Returns:
            Baseline listo para usar.
        """
        path = Path(self.settings.baseline_path)
        baseline: Baseline | None = None
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                logger.info("Baseline cargado de archivo", extra={"path": str(path)})
                baseline = Baseline.from_json(data)
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning(
                    "Baseline ilegible, se recalculará", extra={"error": str(exc)}
                )
        if baseline is None:
            baseline = self._build()
            self._persist(baseline, path)
        self._log_baseline(baseline)
        return baseline

    def _log_baseline(self, baseline: Baseline) -> None:
        """Loguea los valores del baseline y advierte si la JVM quedó en 0.

        Args:
            baseline: baseline en uso.
        """
        logger.info("Baseline en uso", extra={"baseline": baseline.values})
        if not baseline.get("jvm_res_mb"):
            logger.warning(
                "Baseline con jvm_res_mb=0: la JVM no fue detectada al calcularlo. "
                "El DoS no tendrá referencia de memoria de la JVM. Ajustá "
                "JVM_CMDLINE_MATCH, verificá pid=host y recalculá (borrá baseline.json)."
            )

    def _build(self) -> Baseline:
        """Calcula el baseline muestreando estado normal N segundos.

        Returns:
            Baseline promediado.
        """
        warmup = self.settings.baseline_warmup_seconds
        interval = self.settings.baseline_sample_interval_seconds
        logger.info(
            "Calculando baseline (asume ausencia de ataque)",
            extra={"warmup_s": warmup, "interval_s": interval},
        )
        samples: list[HostMetricsSnapshot] = []
        elapsed = 0.0
        while elapsed < warmup:
            samples.append(self.collector.collect())
            time.sleep(interval)
            elapsed += interval

        return Baseline(values=_average_metrics(samples))

    def _persist(self, baseline: Baseline, path: Path) -> None:
        """Persiste el baseline a disco.

        Args:
            baseline: baseline a guardar.
            path: ruta destino.
        """
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(baseline.to_json(), indent=2), encoding="utf-8"
            )
            logger.info("Baseline persistido", extra={"path": str(path)})
        except OSError as exc:
            logger.warning("No se pudo persistir el baseline", extra={"error": str(exc)})


def _average_metrics(samples: list[HostMetricsSnapshot]) -> dict[str, float]:
    """Promedia las métricas relevantes de una lista de snapshots.

    Args:
        samples: snapshots de host capturados en estado normal.

    Returns:
        Mapa métrica -> promedio.
    """
    if not samples:
        return {}

    def avg(getter) -> float:
        vals = [getter(s) for s in samples if getter(s) is not None]
        return round(sum(vals) / len(vals), 2) if vals else 0.0

    return {
        "host_cpu_percent": avg(lambda s: s.cpu_percent),
        "total_tasks": avg(lambda s: s.total_tasks),
        "user_threads": avg(lambda s: s.user_threads),
        "kernel_threads": avg(lambda s: s.kernel_threads),
        "jvm_res_mb": avg(lambda s: s.jvm.res_mb if s.jvm else None),
        "jvm_virt_mb": avg(lambda s: s.jvm.virt_mb if s.jvm else None),
        "jvm_num_threads": avg(lambda s: s.jvm.num_threads if s.jvm else None),
        "jvm_cpu_percent": avg(lambda s: s.jvm.cpu_percent if s.jvm else None),
    }


# Mapeo métrica del YAML -> getter sobre el snapshot de host.
_METRIC_GETTERS = {
    "host_cpu_percent": lambda s: s.cpu_percent,
    "total_tasks": lambda s: float(s.total_tasks),
    "user_threads": lambda s: float(s.user_threads),
    "kernel_threads": lambda s: float(s.kernel_threads),
    "jvm_res_mb": lambda s: s.jvm.res_mb if s.jvm else None,
    "jvm_virt_mb": lambda s: s.jvm.virt_mb if s.jvm else None,
    "jvm_num_threads": lambda s: float(s.jvm.num_threads) if s.jvm else None,
    "jvm_cpu_percent": lambda s: s.jvm.cpu_percent if s.jvm else None,
}


class DosThresholdCheck(CheckBase):
    """Check volumétrico de umbrales relativos para el DoS de Netty."""

    check_id = "dos_thresholds"
    cve_id = CVE_ID

    def __init__(
        self,
        cve_def: CveDefinition,
        baseline: Baseline,
        settings: Settings | None = None,
    ) -> None:
        """Inicializa el check.

        Args:
            cve_def: definición YAML de CVE-2026-33871.
            baseline: baseline de estado normal.
            settings: configuración opcional.
        """
        self.cve_def = cve_def
        self.baseline = baseline
        self.settings = settings or get_settings()
        sig = cve_def.expected_signatures or {}
        self.thresholds: dict[str, dict[str, Any]] = sig.get("thresholds", {})
        self.sustained_required: int = int(sig.get("sustained_samples", 1))
        # Historial de muestras para evaluar persistencia ("sostenido").
        self._breach_streaks: dict[str, int] = {}

    def run(self, **kwargs: Any) -> list[CheckResult]:
        """Evalúa el snapshot actual contra los umbrales relativos.

        Args:
            **kwargs: debe incluir ``host_snapshot`` (HostMetricsSnapshot).

        Returns:
            Lista con un único ``CheckResult`` agregando todas las métricas.
        """
        snapshot: HostMetricsSnapshot | None = kwargs.get("host_snapshot")
        if snapshot is None:
            collector = HostMetricsCollector(self.settings)
            snapshot = collector.collect()

        breaches: dict[str, Any] = {}
        for metric, rule in self.thresholds.items():
            getter = _METRIC_GETTERS.get(metric)
            if getter is None:
                continue
            current = getter(snapshot)
            if current is None:
                continue
            limit = self._limit_for(metric, rule)
            direction = rule.get("direction", "above")
            breached = current > limit if direction == "above" else current < limit
            if breached:
                self._breach_streaks[metric] = self._breach_streaks.get(metric, 0) + 1
            else:
                self._breach_streaks[metric] = 0
            sustained = self._breach_streaks[metric] >= self.sustained_required
            if breached:
                breaches[metric] = {
                    "current": current,
                    "limit": round(limit, 2),
                    "baseline": self.baseline.get(metric),
                    "streak": self._breach_streaks[metric],
                    "sustained": sustained,
                }

        sustained_breaches = {
            m: d for m, d in breaches.items() if d["sustained"]
        }
        # Disparo: CPU del host saturada Y Keycloak demostrablemente como
        # consumidor (precisión / anti-falso-positivo). El CONTINUATION flood es
        # CPU-bound: satura la CPU pero NO crece en threads/memoria. El ancla a
        # Keycloak es que su PROCESO JVM esté quemando CPU (jvm_cpu_percent); si
        # el 100% de CPU viniera de un proceso AJENO a Keycloak, su JVM no
        # aparecería como consumidora y NO se alerta. Se aceptan también las
        # anclas de threads (host/JVM) por si otra variante del ataque sí las mueve.
        sustained_ids = set(sustained_breaches)
        host_cpu_saturated = "host_cpu_percent" in sustained_ids
        keycloak_anchor = sustained_ids & {
            "jvm_cpu_percent",
            "jvm_num_threads",
            "user_threads",
        }
        triggered = host_cpu_saturated and bool(keycloak_anchor)
        score = min(1.0, len(sustained_breaches) / max(1, len(self.thresholds)))

        # Visibilidad por ciclo: si hay CUALQUIER métrica sobre umbral (aunque no
        # alcance para disparar), se loguea qué rompió y su streak. Es el
        # equivalente DoS del heartbeat de percepción del OIDC: permite calibrar
        # viendo exactamente qué mide el agente durante el ataque.
        if breaches:
            logger.info(
                "DoS: métricas sobre umbral",
                extra={
                    "sobre_umbral": {
                        m: {
                            "actual": d["current"],
                            "limite": d["limit"],
                            "streak": d["streak"],
                            "sostenido": d["sustained"],
                        }
                        for m, d in breaches.items()
                    },
                    "sostenidas": sorted(sustained_ids),
                    "condicion": "host_cpu + (jvm_cpu|jvm_num_threads|user_threads)",
                    "dispararia": triggered,
                },
            )

        result = CheckResult(
            check_id=self.check_id,
            name="Umbrales volumétricos DoS (Netty CONTINUATION flood)",
            cve_id=self.cve_id,
            triggered=triggered,
            severity=self.cve_def.severity if triggered else "info",
            score=round(score, 2),
            message=(
                f"{len(sustained_breaches)} métricas superan umbral sostenido"
                if triggered
                else "Métricas dentro de rangos normales o picos no sostenidos"
            ),
            evidence={
                "breaches": breaches,
                "sustained_breaches": sustained_breaches,
                "snapshot": snapshot.model_dump(mode="json"),
                "baseline": self.baseline.values,
            },
        )
        return [result]

    def _limit_for(self, metric: str, rule: dict[str, Any]) -> float:
        """Calcula el umbral efectivo de una métrica.

        Combina el factor relativo al baseline con un piso absoluto opcional.

        Args:
            metric: nombre de la métrica.
            rule: regla del YAML (``factor``, ``absolute_floor``, ...).

        Returns:
            Umbral numérico contra el que comparar.
        """
        base = self.baseline.get(metric, 0.0)
        factor = float(rule.get("factor", 1.0))
        relative_limit = base * factor
        floor = rule.get("absolute_floor")
        if floor is not None:
            # Para "above" el umbral efectivo es el mayor entre el piso y el
            # relativo; así evita disparar si el baseline ya es alto pero exige
            # como mínimo superar el piso absoluto.
            return max(float(floor), relative_limit)
        return relative_limit
