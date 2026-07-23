"""Construcción y esquema de la alerta estructurada."""

from .builder import AlertBuilder, max_severity
from .schema import AffectedComponent, Alert, DetectedCVE, Evidence
from .sink import AlertSink

__all__ = [
    "AlertBuilder",
    "max_severity",
    "AffectedComponent",
    "Alert",
    "DetectedCVE",
    "Evidence",
    "AlertSink",
]
