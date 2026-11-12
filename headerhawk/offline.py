"""Offline mode: analyze headers saved from a proxy, curl -i, or Burp.

This is the "offline analyzer" half of HeaderHawk: paste or pipe raw HTTP
response headers and get the same scored report without touching the network.
"""

from __future__ import annotations

import re
import sys

from .checks import Headers


_STATUS_LINE_RE = re.compile(r"^HTTP/\d+(?:\.\d+)?\s+\d{3}\b")


def _split_response_blocks(text: str) -> list[list[str]]:
    """Split a raw dump into one header block per HTTP response.

    A ``curl -i`` dump of a redirecting URL holds several responses back
    to back: each starts with a status line and ends at the blank line
    before its body. Blocks are returned in order; a dump with no status
    line at all is a single block, so pasted header-only dumps parse
    exactly as before. Body lines (after a response's blank line) are
    never headers, even when they contain a colon.
    """
    blocks: list[list[str]] = []
    current: list[str] = []
    in_response = False
    for raw_line in text.splitlines():
        line = raw_line.rstrip("\r\n")
        if _STATUS_LINE_RE.match(line):
            if current or in_response:
                blocks.append(current)
            current = []
            in_response = True
            continue
        if in_response and not line.strip():
            # End of this response's headers; the body follows.
            blocks.append(current)
            current = []
            in_response = False
            continue
        if in_response or not blocks:
            current.append(line)
        # Anything else is a response body line: ignored, never parsed.
    if current or in_response:
        blocks.append(current)
    return blocks


def parse_raw_headers(text: str) -> Headers:
    """Parse raw HTTP response headers into {lowercased-name: [values]}.

    Tolerates a leading status line ("HTTP/1.1 200 OK"), blank lines,
    duplicate headers, and obsolete line folding. When the dump holds
    several responses (``curl -i`` on a redirecting URL), only the last
    block — the final response — is parsed; earlier blocks' headers and
    every response body are ignored.
    """
    headers: Headers = {}
    current: str | None = None
    blocks = _split_response_blocks(text)
    lines = blocks[-1] if blocks else []
    for raw_line in lines:
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
