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
from diagnostics import get_diagnostics

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


def _latest_report(reports_dir: Path) -> Path | None:
    """Devuelve el reporte de validación más reciente, o ``None`` si no hay.

    Ignora ``comparison.json`` (artefacto especial de la comparativa). Así el
    submódulo de resultados siempre muestra la última campaña generada.
    """
    try:
        candidates = [
            p for p in reports_dir.glob("*.json") if p.name != "comparison.json"
        ]
    except OSError:
        return None
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)


def _make_handler(dashboard_dir: Path, alerts_file: Path, reports_dir: Path, diagnostics_file: Path):
    """Crea el handler HTTP ligado al dashboard, alertas, reportes y diagnóstico.

    Args:
        dashboard_dir: directorio con index.html/styles.css/app.js.
        alerts_file: ruta al ``alerts.jsonl`` que escribe el agente.
        reports_dir: directorio de reportes de validación (MD/JSON).
        diagnostics_file: ruta al snapshot de diagnóstico del agente.

    Returns:
        Clase handler para ``ThreadingHTTPServer``.
    """

    class DashboardHandler(BaseHTTPRequestHandler):
        """Handler de solo lectura: dashboard estático + alertas + resultados."""

        def log_message(self, *args) -> None:  # noqa: D401, ANN002
            """Silencia el log por-request (ruidoso) del servidor base."""

        def do_GET(self) -> None:  # noqa: N802 - nombre impuesto por la stdlib
            """Resuelve las rutas del dashboard, las alertas y los resultados."""
            path = urlparse(self.path).path
            if path in ("/", "/index.html"):
                self._send(dashboard_dir / "index.html")
            elif path == "/data/alerts/alerts.jsonl":
                # Si aún no existe (sin alertas), 404 → el dashboard lo muestra
                # como "sin alertas aún".
                self._send(alerts_file, ctype="application/x-ndjson; charset=utf-8")
            elif path == "/data/validation/latest.json":
                # Último reporte de validación (lo genera validation_cli). 404 si
                # todavía no se corrió ninguna campaña → el panel lo indica.
                latest = _latest_report(reports_dir)
                if latest is None:
                    self.send_error(404)
                else:
                    self._send(latest, ctype="application/json; charset=utf-8")
            elif path == "/data/validation/comparison.json":
                # Comparativa LLM vs --no-llm (opcional; la persiste `compare --save`).
                self._send(reports_dir / "comparison.json",
                           ctype="application/json; charset=utf-8")
            elif path == "/data/diagnostics.json":
                # Diagnóstico del agente (mensajes específicos). 404 si aún no hay.
                self._send(diagnostics_file, ctype="application/json; charset=utf-8")
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
    reports_dir = Path(settings.validation_reports_dir)
    diagnostics_file = Path(settings.diagnostics_path)
    handler = _make_handler(dashboard_dir, alerts_file, reports_dir, diagnostics_file)

    try:
        server = ThreadingHTTPServer(
            (settings.dashboard_host, settings.dashboard_port), handler
        )
    except OSError as exc:
        logger.warning(
            "No se pudo iniciar el dashboard embebido (¿puerto ocupado?)",
            extra={"port": settings.dashboard_port, "error": str(exc)},
        )
        get_diagnostics(settings).report(
            "dashboard",
            "warn",
            f"El dashboard embebido no arrancó (puerto {settings.dashboard_port} ocupado)",
            "Liberá el puerto (no levantes un http.server manual) y reiniciá el agente.",
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
    get_diagnostics(settings).report(
        "dashboard", "ok",
        f"Dashboard embebido activo en el puerto {settings.dashboard_port}",
    )
    return server
