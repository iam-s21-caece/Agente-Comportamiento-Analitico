"""Configuración de pytest: asegura que el paquete del agente esté en sys.path."""

from __future__ import annotations

import sys
from pathlib import Path

# Permite ``import config``, ``import signal_collector`` etc. al correr pytest
# desde cualquier directorio.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
