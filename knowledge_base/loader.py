"""Carga y acceso a las definiciones estructuradas de CVEs.

Las definiciones viven como archivos YAML en ``knowledge_base/cves/`` y se cargan
una vez al iniciar el agente. Representan el "conocimiento previo" del agente
(modelo del mundo de Russell & Norvig): qué vulnerabilidades existen, qué firmas
esperar y a qué componente arquitectural pertenecen.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from config.logging_config import get_logger

logger = get_logger(__name__)


class AffectedComponent(BaseModel):
    """Componente arquitectural afectado por una CVE."""

    layer: str
    stack: list[str] = Field(default_factory=list)
    specific_module: str = ""


class CveDefinition(BaseModel):
    """Definición estructurada de una CVE cargada desde YAML."""

    id: str
    name: str
    affected_component: AffectedComponent
    evidence_type: str
    expected_signatures: dict[str, Any] = Field(default_factory=dict)
    detection_strategy: str = ""
    baseline_required: bool = False
    severity: str = "medium"


class KnowledgeBase(BaseModel):
    """Conjunto de definiciones de CVE indexadas por id."""

    cves: dict[str, CveDefinition] = Field(default_factory=dict)

    def get(self, cve_id: str) -> CveDefinition | None:
        """Devuelve la definición de una CVE por su id.

        Args:
            cve_id: identificador (p.ej. ``CVE-2023-0264``).

        Returns:
            La definición, o ``None`` si no existe.
        """
        return self.cves.get(cve_id.upper())

    def by_evidence_type(self, evidence_type: str) -> list[CveDefinition]:
        """Filtra las CVEs por tipo de evidencia.

        Args:
            evidence_type: ``volumetric_metrics`` o ``correlated_events``.

        Returns:
            Lista de definiciones que coinciden.
        """
        return [c for c in self.cves.values() if c.evidence_type == evidence_type]


def load_knowledge_base(cves_dir: Path) -> KnowledgeBase:
    """Carga todas las definiciones YAML de un directorio.

    Args:
        cves_dir: directorio que contiene los ``*.yaml`` de CVEs.

    Returns:
        KnowledgeBase poblada. Si un archivo es inválido se loguea y se omite.
    """
    kb = KnowledgeBase()
    if not cves_dir.exists():
        logger.warning("Directorio de CVEs inexistente", extra={"dir": str(cves_dir)})
        return kb

    for path in sorted(cves_dir.glob("*.yaml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            definition = CveDefinition.model_validate(data)
            kb.cves[definition.id.upper()] = definition
            logger.info("CVE cargada", extra={"cve_id": definition.id})
        except Exception as exc:  # noqa: BLE001 - robustez: no crashear por un YAML
            logger.error(
                "Error cargando definición de CVE",
                extra={"path": str(path), "error": str(exc)},
            )
    return kb
