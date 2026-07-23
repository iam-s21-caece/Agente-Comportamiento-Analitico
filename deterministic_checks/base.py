"""Interfaz y modelos comunes de los checks deterministas.

Los checks deterministas son la mitad "no-LLM" del agente híbrido (patrón
inspirado en ``iam-auditor``): aplican reglas explícitas y reproducibles sobre
las señales y emiten ``CheckResult``. El LLM luego razona sobre estos resultados.
"""

from __future__ import annotations

import abc
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

Severity = str  # "info" | "low" | "medium" | "high" | "critical"


class CheckResult(BaseModel):
    """Resultado de un check determinista."""

    check_id: str
    name: str
    cve_id: str
    triggered: bool
    severity: Severity = "info"
    # score en [0, 1]: confianza/intensidad de la señal detectada.
    score: float = 0.0
    message: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CheckBase(abc.ABC):
    """Interfaz base de todos los checks deterministas."""

    #: Identificador estable del check.
    check_id: str = "base"
    #: CVE asociada al check.
    cve_id: str = ""

    @abc.abstractmethod
    def run(self, **kwargs: Any) -> list[CheckResult]:
        """Ejecuta el check y devuelve sus resultados.

        Args:
            **kwargs: insumos específicos del check (snapshots, eventos, etc.).

        Returns:
            Lista de ``CheckResult`` (puede ser vacía si no aplica).
        """
        raise NotImplementedError
