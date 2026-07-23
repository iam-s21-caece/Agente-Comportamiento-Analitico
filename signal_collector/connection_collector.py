"""Colector de conexiones TCP hacia Keycloak, agregadas por IP de origen.

Atribuye el ORIGEN de un flood volumétrico (CVE-2026-33871): identifica la(s)
IP(s) con concurrencia anómala hacia el puerto de Keycloak. Complementa a las
métricas de CPU (que dicen "hay saturación") con el "desde dónde".

Lee ``/proc/net/tcp`` y ``/proc/net/tcp6`` directamente (no vía psutil) para no
escanear ``/proc/<pid>/fd`` de todos los procesos —costoso y frágil justo bajo el
flood, cuando el host está agotando descriptores—. Como el agente corre con
``network_mode: host``, esta tabla es la del host: expone la IP del cliente
ANTES del NAT de Docker (a diferencia de lo que ve la JVM dentro del contenedor).

Nota de topología: si el ataque entra por túnel SSH o localhost, el origen será
loopback (127.0.0.1); si entra por la red de Docker, el gateway (172.x). En
ambos casos la IP real queda enmascarada y el snapshot lo marca (``masked``); la
CONCURRENCIA, en cambio, es siempre real y correlaciona con la saturación.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path
from urllib.parse import urlparse

from config.logging_config import get_logger
from config.settings import Settings, get_settings

from .base import ConnectionSnapshot, RemoteTalker, SignalCollector

logger = get_logger(__name__)

# Estados de /proc/net/tcp que cuentan como conexión "activa" del flood:
# 01 = ESTABLISHED (handshake completo, enviando frames), 03 = SYN_RECV (half-open).
_ACTIVE_STATES = {"01", "03"}
_MAX_TALKERS = 5


class ConnectionCollector(SignalCollector[ConnectionSnapshot]):
    """Enumera conexiones al puerto de Keycloak y las agrega por IP de origen."""

    def __init__(self, settings: Settings | None = None) -> None:
        """Inicializa el colector.

        Args:
            settings: configuración; si se omite se usa la global.
        """
        self.settings = settings or get_settings()
        self.port = self._parse_port(self.settings.keycloak_base_url)

    @staticmethod
    def _parse_port(base_url: str) -> int:
        """Extrae el puerto de Keycloak de su base URL (default 8443)."""
        try:
            return urlparse(base_url).port or 8443
        except (ValueError, TypeError):
            return 8443

    def collect(self) -> ConnectionSnapshot:
        """Captura las conexiones activas hacia el puerto de Keycloak.

        Returns:
            ConnectionSnapshot con los top-talkers por IP. Nunca propaga
            excepciones: cualquier error queda en el campo ``error``.
        """
        snap = ConnectionSnapshot(keycloak_port=self.port)
        try:
            counts: dict[str, int] = {}
            self._accumulate("/proc/net/tcp", is_v6=False, counts=counts)
            self._accumulate("/proc/net/tcp6", is_v6=True, counts=counts)

            snap.total_connections = sum(counts.values())
            snap.unique_ips = len(counts)
            ordered = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)
            snap.top_talkers = [
                RemoteTalker(ip=ip, connections=n, scope=_scope(ip))
                for ip, n in ordered[:_MAX_TALKERS]
            ]
            if snap.top_talkers:
                top = snap.top_talkers[0]
                snap.masked = top.scope in ("loopback", "private")
                if snap.masked:
                    snap.note = (
                        f"Origen aparente {top.ip} ({top.scope}) con {top.connections} "
                        "conexiones: IP real probablemente enmascarada por NAT/proxy/"
                        "túnel. La concurrencia es real y correlaciona con la saturación."
                    )
                else:
                    snap.note = (
                        f"Origen {top.ip} con {top.connections} conexiones concurrentes "
                        "hacia Keycloak."
                    )
        except OSError as exc:
            logger.error("Error leyendo tabla de conexiones", extra={"error": str(exc)})
            snap.error = str(exc)
        return snap

    def _accumulate(self, path: str, is_v6: bool, counts: dict[str, int]) -> None:
        """Suma al mapa ``counts`` las conexiones activas al puerto de Keycloak.

        Args:
            path: ruta a ``/proc/net/tcp`` o ``/proc/net/tcp6``.
            is_v6: ``True`` si la tabla es IPv6.
            counts: acumulador ``{ip_origen: nº_conexiones}`` (se muta in-place).
        """
        try:
            lines = Path(path).read_text(encoding="utf-8").splitlines()
        except OSError:
            return  # la tabla puede no existir (p. ej. sin IPv6); no es error fatal
        for line in lines[1:]:  # saltar cabecera
            parts = line.split()
            if len(parts) < 4:
                continue
            local_addr, rem_addr, state = parts[1], parts[2], parts[3]
            if state not in _ACTIVE_STATES:
                continue
            if _hex_port(local_addr) != self.port:
                continue
            ip = _decode_hex_ip(rem_addr.rsplit(":", 1)[0], is_v6)
            if ip:
                counts[ip] = counts.get(ip, 0) + 1


def _hex_port(addr: str) -> int:
    """Extrae el puerto (hex) de un campo ``IP:PORT`` de /proc/net/tcp."""
    try:
        return int(addr.rsplit(":", 1)[1], 16)
    except (IndexError, ValueError):
        return -1


def _decode_hex_ip(hex_ip: str, is_v6: bool) -> str | None:
    """Decodifica la IP hexadecimal (little-endian) de /proc/net/tcp.

    Args:
        hex_ip: IP en hexadecimal como la almacena el kernel.
        is_v6: ``True`` para IPv6 (16 bytes en 4 words little-endian).

    Returns:
        La IP en texto, o ``None`` si no se pudo decodificar.
    """
    try:
        raw = bytes.fromhex(hex_ip)
        if is_v6:
            # 4 words de 4 bytes, cada uno little-endian.
            raw = b"".join(raw[i : i + 4][::-1] for i in range(0, 16, 4))
        else:
            raw = raw[::-1]  # 4 bytes little-endian
        return str(ipaddress.ip_address(raw))
    except (ValueError, IndexError):
        return None


def _scope(ip: str) -> str:
    """Clasifica una IP como loopback / private / public."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "public"
    if addr.is_loopback:
        return "loopback"
    if addr.is_private:
        return "private"
    return "public"
