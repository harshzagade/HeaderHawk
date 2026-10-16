"""TLS version/cipher sniffing, stdlib ssl only.

No nmap/sslyze dependency: HeaderHawk opens real TLS handshakes and asks the
server which protocol versions it will negotiate. For each of TLS 1.0..1.3 a
context restricted to that single version is built; a successful handshake
means the server still accepts the version. One extra default handshake
captures the negotiated version and cipher.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass


_VERSIONS: list[tuple[str, ssl.TLSVersion]] = [
    ("TLSv1", ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
]


@dataclass
class TLSInfo:
    """Result of probing a server's TLS support.

    ``versions`` holds the protocol versions the server negotiated
    successfully (e.g. ``("TLSv1.2", "TLSv1.3")``). ``negotiated`` and
    ``cipher`` come from a separate default handshake. ``error`` is set when
    even the default handshake failed; ``versions`` is then empty.
    """

    host: str
    port: int = 443
    versions: tuple[str, ...] = ()
    negotiated: str = ""
    cipher: str = ""
    cipher_bits: int = 0
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "versions": list(self.versions),
            "negotiated": self.negotiated,
            "cipher": self.cipher,
            "cipher_bits": self.cipher_bits,
            "error": self.error,
        }


def _connect(host: str, port: int, timeout: float,
             context: ssl.SSLContext) -> ssl.SSLSocket:
    """TCP-connect and wrap the socket. SNI is always sent (server_hostname)."""
    raw = socket.create_connection((host, port), timeout=timeout)
    try:
        return context.wrap_socket(raw, server_hostname=host)
    except Exception:
        raw.close()
        raise


def _single_version_context(version: ssl.TLSVersion) -> ssl.SSLContext | None:
    """Context restricted to exactly one TLS version, or None when the local
    OpenSSL cannot build it (then the version is skipped, not reported)."""
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = version
        context.maximum_version = version
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    except (ssl.SSLError, ValueError, AttributeError):
        return None
    return context


def probe_tls(host: str, port: int = 443, timeout: float = 5.0) -> TLSInfo:
    """Probe which TLS versions *host* accepts, plus the negotiated cipher.

    Certificate validation is disabled on purpose: this probe audits the
    server's *protocol* posture, not its certificate chain (that is a
    different check). Handshake failures are never fatal — they mean the
    server refused that version, which is exactly the signal we want.
    """
    info = TLSInfo(host=host, port=port)
    supported: list[str] = []
    for label, version in _VERSIONS:
        context = _single_version_context(version)
        if context is None:
            continue
        try:
            with _connect(host, port, timeout, context):
                supported.append(label)
        except (ssl.SSLError, OSError, socket.timeout, TimeoutError):
            pass
    info.versions = tuple(supported)

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with _connect(host, port, timeout, context) as tls:
            info.negotiated = tls.version() or ""
            cipher = tls.cipher()
            if cipher:
                info.cipher = cipher[0]
                info.cipher_bits = cipher[2]
    except Exception as exc:  # noqa: BLE001 - any failure becomes an INFO note
        info.error = str(exc) or type(exc).__name__
    return info
