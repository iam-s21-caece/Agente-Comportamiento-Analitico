"""Capa de trazabilidad: registro observacional del ciclo agéntico.

Se engancha en el loop ReAct sin modificar su lógica y persiste cada decisión
en JSONL consultable, con un logger de auditoría correlacionado por ids.
"""

from .audit_logger import AuditLogger
from .trace_query import get_analysis_events, iter_events
from .trace_recorder import TraceEvent, TraceRecorder
from .trace_store import TraceStore

__all__ = [
    "AuditLogger",
    "TraceRecorder",
    "TraceEvent",
    "TraceStore",
    "iter_events",
    "get_analysis_events",
]
