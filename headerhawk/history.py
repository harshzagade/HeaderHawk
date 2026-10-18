"""Grade history: record one (timestamp, url, grade, score) row per audit run.

The history file is newline-delimited JSON (one object per line), so it
stays append-friendly and human-inspectable. Malformed lines are skipped on
read with a count, never a crash — a history file grows over months and one
bad line should not hide the rest.
"""

from __future__ import annotations

import datetime
import json
from dataclasses import dataclass


@dataclass
class HistoryEntry:
    """One recorded audit run."""

    timestamp: str   # ISO-8601 UTC, e.g. "2026-10-18T04:52:11Z"
    url: str
    grade: str
    score: int

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "url": self.url,
            "grade": self.grade,
            "score": self.score,
        }


def _utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


def append_run(path: str, url: str, grade: str, score: int) -> None:
    """Append one history row to *path*.

    Raises OSError when the file cannot be written — the caller decides how
    to surface it (the CLI treats it as a hard error: silent data loss is
    worse than a non-zero exit).
    """
    entry = HistoryEntry(timestamp=_utc_now_iso(), url=url,
                         grade=grade, score=int(score))
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry.to_dict()) + "\n")


def read_history(path: str) -> tuple[list[HistoryEntry], int]:
    """Read *path*, returning (entries, skipped_malformed_count).

    Rows must be JSON objects with string ``timestamp``/``url``/``grade``
    and an integer ``score``; anything else (bad JSON, missing keys, wrong
    types) is counted as malformed and skipped.

    Raises OSError when the file cannot be read, ValueError when it is not
    UTF-8-decodable.
    """
    entries: list[HistoryEntry] = []
    skipped = 0
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.readlines()
    except UnicodeDecodeError as exc:
        raise ValueError(f"history file {path!r} is not valid UTF-8: {exc}") from exc
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            skipped += 1
            continue
        if (
            not isinstance(payload, dict)
            or not isinstance(payload.get("timestamp"), str)
            or not isinstance(payload.get("url"), str)
            or not isinstance(payload.get("grade"), str)
            or not isinstance(payload.get("score"), int)
        ):
            skipped += 1
            continue
        entries.append(HistoryEntry(
            timestamp=payload["timestamp"],
            url=payload["url"],
            grade=payload["grade"],
            score=payload["score"],
        ))
    return entries, skipped
