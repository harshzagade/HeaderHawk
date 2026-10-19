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
from datetime import datetime, timezone


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
    cert_not_after: str = ""       # raw notAfter string from the leaf cert
    cert_days_left: int | None = None  # whole days until expiry; None = unknown

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "versions": list(self.versions),
            "negotiated": self.negotiated,
            "cipher": self.cipher,
            "cipher_bits": self.cipher_bits,
            "error": self.error,
            "cert_not_after": self.cert_not_after,
            "cert_days_left": self.cert_days_left,
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


def _cert_days_left(peercert: dict | None) -> int | None:
    """Whole days until the leaf certificate expires, or None if unknown.

    ``getpeercert()`` returns ``{'notAfter': 'Nov 18 10:20:00 2026 GMT', ...}``
    when certificate verification is off (which this probe deliberately
    uses). A negative result means the certificate already expired.
    """
    if not isinstance(peercert, dict):
        return None
    not_after = peercert.get("notAfter")
    if not not_after:
        return None
    try:
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        expiry = expiry.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None
    delta = expiry - datetime.now(timezone.utc)
    return int(delta.total_seconds() // 86400)


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
            # Certificate expiry is read off the same handshake: no extra
            # connection. Missing getpeercert (old stubs) -> unknown, silent.
            getpeercert = getattr(tls, "getpeercert", None)
            if getpeercert is not None:
                try:
                    cert = getpeercert()
                except Exception:  # noqa: BLE001 - cert unreadable -> unknown
                    cert = None
                if isinstance(cert, dict):
                    info.cert_not_after = str(cert.get("notAfter") or "")
                info.cert_days_left = _cert_days_left(cert)
    except Exception as exc:  # noqa: BLE001 - any failure becomes an INFO note
        info.error = str(exc) or type(exc).__name__
    return info
