"""Offline mode: analyze headers saved from a proxy, curl -i, or Burp.

This is the "offline analyzer" half of HeaderHawk: paste or pipe raw HTTP
response headers and get the same scored report without touching the network.
"""

from __future__ import annotations

import sys

from .checks import Headers


def parse_raw_headers(text: str) -> Headers:
    """Parse raw HTTP response headers into {lowercased-name: [values]}.

    Tolerates a leading status line ("HTTP/1.1 200 OK"), blank lines,
    duplicate headers, and obsolete line folding.
    """
    headers: Headers = {}
    current: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.rstrip("\r\n")
        if not line.strip():
            continue
        if line[0] in (" ", "\t") and current is not None:
            # Obsolete RFC 7230 line folding: continuation of previous header.
            headers[current][-1] += " " + line.strip()
            continue
        if ":" not in line:
            continue  # status line or stray text
        name, _, value = line.partition(":")
        name = name.strip().lower()
        if not name or any(ch.isspace() for ch in name):
            continue  # not a real header line
        current = name
        headers.setdefault(name, []).append(value.strip())
    return headers


def load_headers(path: str | None) -> Headers:
    """Load headers from a file, or from stdin when path is None/'-'."""
    if path is None or path == "-":
        text = sys.stdin.read()
        source = "<stdin>"
    else:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        source = path
    headers = parse_raw_headers(text)
    if not headers:
        raise ValueError(f"No HTTP headers found in {source}.")
    return headers
