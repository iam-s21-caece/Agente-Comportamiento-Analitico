"""Colector de métricas del host y de la JVM de Keycloak (psutil + /proc).

Captura CPU, conteo de tasks/threads (separando threads de usuario de kernel) y
las métricas de memoria del proceso JVM (VIRT/RES/SHR), localizado por su
cmdline. Estas son las señales volumétricas centrales para CVE-2026-33871.
"""

from __future__ import annotations

import psutil

from config.logging_config import get_logger
from config.settings import Settings, get_settings

from .base import HostMetricsSnapshot, JvmProcessInfo, SignalCollector

logger = get_logger(__name__)


class HostMetricsCollector(SignalCollector[HostMetricsSnapshot]):
    """Captura métricas del host y del proceso JVM de Keycloak."""

    def __init__(self, settings: Settings | None = None) -> None:
        """Inicializa el colector.

        Args:
            settings: configuración; si se omite se usa la global.
        """
        self.settings = settings or get_settings()

    def collect(self) -> HostMetricsSnapshot:
        """Captura un snapshot de métricas del host y la JVM.

        Returns:
            HostMetricsSnapshot con CPU, threads y datos de la JVM. Cualquier
            error se reporta en el campo ``error`` sin propagar excepciones.
        """
        snapshot = HostMetricsSnapshot()
        try:
            # interval=0.5 toma una medición real de CPU (no acumulada).
            snapshot.cpu_percent = psutil.cpu_percent(interval=0.5)
            user_threads, kernel_threads, total, jvm = self._scan_processes()
            snapshot.user_threads = user_threads
            snapshot.kernel_threads = kernel_threads
            snapshot.total_tasks = total
            snapshot.jvm = jvm
        except OSError as exc:
            # EMFILE ("Too many open files") puede ocurrir por el PROPIO flood DoS:
            # bajo saturación de descriptores el agente compite por fds justo
            # cuando más los necesita. Se reporta distinto para no confundirlo
            # con un bug del colector.
            logger.error(
                "Métricas de host degradadas por límite de recursos "
                "(¿descriptores agotados por el flood?). Subí 'nofile' del "
                "contenedor del agente.",
                extra={"error": str(exc), "errno": getattr(exc, "errno", None)},
            )
            snapshot.error = str(exc)
        except Exception as exc:  # noqa: BLE001 - robustez del colector
            logger.error("Error capturando métricas de host", extra={"error": str(exc)})
            snapshot.error = str(exc)
        return snapshot

    def self_check(self) -> None:
        """Diagnóstico de arranque de la percepción de host/JVM.

        Loguea si la JVM de Keycloak se detecta y con qué valores. Si NO se
        encuentra, lo advierte explícitamente: es la causa más común de que el
        DoS (CVE-2026-33871) no se corrobore con su firma completa (VIRT/RES/
        threads de la JVM).
        """
        snapshot = self.collect()
        logger.info(
            "Self-check de host",
            extra={
                "cpu_percent": snapshot.cpu_percent,
                "total_tasks": snapshot.total_tasks,
                "user_threads": snapshot.user_threads,
                "kernel_threads": snapshot.kernel_threads,
            },
        )
        if snapshot.jvm is None:
            logger.warning(
                "Self-check: JVM de Keycloak NO detectada (match='%s'). Sin ella "
                "no se capturan VIRT/RES/SHR/threads de la JVM y el DoS quedará "
                "sin su firma. Ajustá JVM_CMDLINE_MATCH y verificá pid=host."
                % self.settings.jvm_cmdline_match
            )
        else:
            jvm = snapshot.jvm
            logger.info(
                "Self-check: JVM de Keycloak detectada",
                extra={
                    "pid": jvm.pid,
                    "virt_mb": jvm.virt_mb,
                    "res_mb": jvm.res_mb,
                    "shr_kb": jvm.shr_kb,
                    "num_threads": jvm.num_threads,
                    "state": jvm.state,
                },
            )

    def _scan_processes(self) -> tuple[int, int, int, JvmProcessInfo | None]:
        """Recorre los procesos UNA sola vez: cuenta threads y ubica la JVM.

        Antes se hacían dos ``process_iter`` por ciclo (uno para threads y otro
        para la JVM); bajo el flood DoS eso duplica la apertura de descriptores
        en ``/proc`` justo cuando el sistema está saturado. Esta pasada única
        cuenta threads de usuario vs kernel (kernel = ``cmdline`` vacío, igual
        que htop) y, en el mismo recorrido, retiene el proceso JVM de Keycloak.

        Returns:
            Tupla ``(user_threads, kernel_threads, total_tasks, jvm)``.
        """
        match = self.settings.jvm_cmdline_match
        user_threads = 0
        kernel_threads = 0
        total_tasks = 0
        jvm_proc: psutil.Process | None = None
        for proc in psutil.process_iter(
            ["pid", "name", "num_threads", "cmdline", "status"]
        ):
            try:
                info = proc.info
                total_tasks += 1
                nthreads = info.get("num_threads") or 1
                cmdline = info.get("cmdline")
                if not cmdline:  # kernel thread
                    kernel_threads += nthreads
                    continue
                user_threads += nthreads
                if jvm_proc is None:
                    name = (info.get("name") or "").lower()
                    is_java = "java" in name or any("java" in part for part in cmdline)
                    if is_java and any(match in part for part in cmdline):
                        jvm_proc = proc
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        jvm: JvmProcessInfo | None = None
        if jvm_proc is not None:
            try:
                jvm = self._read_jvm_info(jvm_proc)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                jvm = None
        else:
            logger.warning("Proceso JVM de Keycloak no encontrado", extra={"match": match})
        return user_threads, kernel_threads, total_tasks, jvm

    @staticmethod
    def _read_jvm_info(proc: psutil.Process) -> JvmProcessInfo:
        """Lee VIRT/RES/SHR, estado y threads de un proceso.

        Args:
            proc: proceso psutil de la JVM.

        Returns:
            JvmProcessInfo con las métricas del proceso.
        """
        mem = proc.memory_info()
        # SHR: en Linux memory_info expone .shared; si no, se reporta 0.
        shr_bytes = getattr(mem, "shared", 0) or 0
        return JvmProcessInfo(
            pid=proc.pid,
            virt_mb=round(mem.vms / (1024 * 1024), 1),
            res_mb=round(mem.rss / (1024 * 1024), 1),
            shr_kb=round(shr_bytes / 1024, 1),
            state=proc.status(),
            num_threads=proc.num_threads(),
            cpu_percent=proc.cpu_percent(interval=None),
        )
