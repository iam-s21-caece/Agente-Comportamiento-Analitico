"""Servidor HTTP embebido para el dashboard.

Sirve los archivos estáticos del dashboard y expone ``alerts.jsonl`` bajo la
misma URL (``/data/alerts/alerts.jsonl``), de modo que el usuario solo tenga que
abrir ``http://<vps>:<puerto>/`` — sin montar un ``http.server`` aparte ni pelear
con rutas relativas. Corre en un thread daemon; si el puerto está ocupado,
loguea y el agente sigue funcionando (el dashboard es opcional).
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from config.logging_config import get_logger
from config.settings import Settings, get_settings

logger = get_logger(__name__)

_CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".jsonl": "application/x-ndjson; charset=utf-8",
    ".json": "application/json; charset=utf-8",
}
# Archivos estáticos del dashboard que se pueden servir directamente.
_STATIC = {"styles.css", "app.js", "sample-alerts.jsonl"}


def _make_handler(dashboard_dir: Path, alerts_file: Path):
    """Crea el handler HTTP ligado al dashboard y al archivo de alertas.

    Args:
        dashboard_dir: directorio con index.html/styles.css/app.js.
        alerts_file: ruta al ``alerts.jsonl`` que escribe el agente.

    Returns:
        Clase handler para ``ThreadingHTTPServer``.
    """

    class DashboardHandler(BaseHTTPRequestHandler):
        """Handler de solo lectura: dashboard estático + alerts.jsonl."""

        def log_message(self, *args) -> None:  # noqa: D401, ANN002
            """Silencia el log por-request (ruidoso) del servidor base."""

        def do_GET(self) -> None:  # noqa: N802 - nombre impuesto por la stdlib
            """Resuelve las rutas del dashboard y del archivo de alertas."""
            path = urlparse(self.path).path
            if path in ("/", "/index.html"):
                self._send(dashboard_dir / "index.html")
            elif path == "/data/alerts/alerts.jsonl":
                # Si aún no existe (sin alertas), 404 → el dashboard lo muestra
                # como "sin alertas aún".
                self._send(alerts_file, ctype="application/x-ndjson; charset=utf-8")
            elif path.lstrip("/") in _STATIC:
                self._send(dashboard_dir / path.lstrip("/"))
            else:
                self.send_error(404)

        def _send(self, file: Path, ctype: str | None = None) -> None:
            """Envía un archivo con headers no-cache, o 404 si no existe.

            Args:
                file: archivo a servir.
                ctype: content-type explícito (si no, se infiere por extensión).
            """
            try:
                data = file.read_bytes()
            except OSError:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header(
                "Content-Type",
                ctype or _CONTENT_TYPES.get(file.suffix, "application/octet-stream"),
            )
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

    return DashboardHandler


def start_dashboard_server(settings: Settings | None = None) -> ThreadingHTTPServer | None:
    """Inicia el servidor del dashboard en un thread daemon.

    Args:
        settings: configuración; si se omite se usa la global.

    Returns:
        El servidor iniciado, o ``None`` si está deshabilitado o el puerto está
        ocupado (en cuyo caso el agente sigue funcionando sin dashboard).
    """
    settings = settings or get_settings()
    if not settings.dashboard_enabled:
        return None

    dashboard_dir = Path(settings.dashboard_dir)
    alerts_file = Path(settings.alerts_dir) / "alerts.jsonl"
    handler = _make_handler(dashboard_dir, alerts_file)

    try:
        server = ThreadingHTTPServer(
            (settings.dashboard_host, settings.dashboard_port), handler
        )
    except OSError as exc:
        logger.warning(
            "No se pudo iniciar el dashboard embebido (¿puerto ocupado?)",
            extra={"port": settings.dashboard_port, "error": str(exc)},
        )
        return None

    thread = threading.Thread(target=server.serve_forever, daemon=True, name="dashboard")
    thread.start()
    logger.info(
        "Dashboard embebido activo",
        extra={
            "url": f"http://{settings.dashboard_host}:{settings.dashboard_port}/",
            "alerts_file": str(alerts_file),
        },
    )
    return server
