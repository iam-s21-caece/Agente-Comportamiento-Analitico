"""Colector de métricas del contenedor de Keycloak.

Intenta primero el SDK oficial de Docker (``docker.from_env()``) y, si no está
disponible, cae a parsear la salida de ``docker stats --no-stream --format json``.
"""

from __future__ import annotations

import json
import subprocess

from config.logging_config import get_logger
from config.settings import Settings, get_settings

from .base import ContainerMetricsSnapshot, SignalCollector

logger = get_logger(__name__)


def _parse_size_to_mb(text: str) -> float:
    """Convierte un tamaño tipo '859MiB' / '1.2GiB' / '512kB' a MB.

    Args:
        text: cadena de tamaño con unidad.

    Returns:
        Valor en MB (float). Devuelve 0.0 si no se puede parsear.
    """
    text = text.strip()
    units = {
        "KIB": 1 / 1024,
        "KB": 1 / 1024,
        "MIB": 1.0,
        "MB": 1.0,
        "GIB": 1024.0,
        "GB": 1024.0,
        "B": 1 / (1024 * 1024),
    }
    for unit, factor in units.items():
        if text.upper().endswith(unit):
            try:
                return round(float(text[: -len(unit)]) * factor, 2)
            except ValueError:
                return 0.0
    return 0.0


class ContainerMetricsCollector(SignalCollector[ContainerMetricsSnapshot]):
    """Captura métricas del contenedor (CPU, memoria, PIDs)."""

    def __init__(self, settings: Settings | None = None) -> None:
        """Inicializa el colector.

        Args:
            settings: configuración; si se omite se usa la global.
        """
        self.settings = settings or get_settings()

    def collect(self) -> ContainerMetricsSnapshot:
        """Captura un snapshot del contenedor.

        Returns:
            ContainerMetricsSnapshot; errores se reportan en ``error``.
        """
        snapshot = ContainerMetricsSnapshot(name=self.settings.container_name)
        try:
            stats = self._collect_via_sdk()
            if stats is None:
                stats = self._collect_via_cli()
            if stats is not None:
                snapshot = stats
        except Exception as exc:  # noqa: BLE001 - robustez del colector
            logger.error(
                "Error capturando métricas de contenedor", extra={"error": str(exc)}
            )
            snapshot.error = str(exc)
        return snapshot

    def _collect_via_sdk(self) -> ContainerMetricsSnapshot | None:
        """Intenta usar el SDK oficial de Docker.

        Returns:
            Snapshot o ``None`` si el SDK no está disponible/falla.
        """
        try:
            import docker  # import perezoso: el SDK es opcional
        except ImportError:
            return None
        try:
            client = docker.from_env()
            container = client.containers.get(self.settings.container_name)
            raw = container.stats(stream=False)
            return self._from_sdk_stats(raw)
        except Exception as exc:  # noqa: BLE001
            logger.debug("SDK de Docker no utilizable", extra={"error": str(exc)})
            return None

    def _from_sdk_stats(self, raw: dict) -> ContainerMetricsSnapshot:
        """Calcula métricas a partir del JSON del SDK de Docker.

        Args:
            raw: diccionario de estadísticas del SDK.

        Returns:
            ContainerMetricsSnapshot poblado.
        """
        cpu_stats = raw.get("cpu_stats", {})
        pre_stats = raw.get("precpu_stats", {})
        cpu_delta = cpu_stats.get("cpu_usage", {}).get("total_usage", 0) - pre_stats.get(
            "cpu_usage", {}
        ).get("total_usage", 0)
        system_delta = cpu_stats.get("system_cpu_usage", 0) - pre_stats.get(
            "system_cpu_usage", 0
        )
        online_cpus = cpu_stats.get("online_cpus", 1) or 1
        cpu_percent = 0.0
        if system_delta > 0 and cpu_delta > 0:
            cpu_percent = (cpu_delta / system_delta) * online_cpus * 100.0

        mem_stats = raw.get("memory_stats", {})
        usage = mem_stats.get("usage", 0)
        limit = mem_stats.get("limit", 0)
        return ContainerMetricsSnapshot(
            name=self.settings.container_name,
            cpu_percent=round(cpu_percent, 2),
            mem_usage_mb=round(usage / (1024 * 1024), 2),
            mem_limit_mb=round(limit / (1024 * 1024), 2),
            mem_percent=round((usage / limit * 100.0) if limit else 0.0, 2),
            pids=raw.get("pids_stats", {}).get("current", 0),
        )

    def _collect_via_cli(self) -> ContainerMetricsSnapshot | None:
        """Fallback: parsea ``docker stats --no-stream --format json``.

        Returns:
            Snapshot o ``None`` si el comando falla.
        """
        try:
            result = subprocess.run(
                [
                    "docker",
                    "stats",
                    "--no-stream",
                    "--format",
                    "{{json .}}",
                    self.settings.container_name,
                ],
                capture_output=True,
                text=True,
                timeout=self.settings.http_timeout_seconds,
                check=True,
            )
        except (subprocess.SubprocessError, FileNotFoundError) as exc:
            logger.error("docker stats falló", extra={"error": str(exc)})
            return None

        line = result.stdout.strip().splitlines()[0] if result.stdout.strip() else ""
        if not line:
            return None
        data = json.loads(line)
        mem_usage, _, mem_limit = data.get("MemUsage", "0B / 0B").partition("/")
        return ContainerMetricsSnapshot(
            name=data.get("Name", self.settings.container_name),
            cpu_percent=float(data.get("CPUPerc", "0%").rstrip("%") or 0),
            mem_usage_mb=_parse_size_to_mb(mem_usage),
            mem_limit_mb=_parse_size_to_mb(mem_limit),
            mem_percent=float(data.get("MemPerc", "0%").rstrip("%") or 0),
            pids=int(data.get("PIDs", 0) or 0),
        )
