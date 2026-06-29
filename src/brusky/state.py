"""SQLite-backed scan state — the memory that makes "daily" meaningful.

Stores every finding ever seen (keyed by ecosystem:name:vuln_id) with the
severity at first sight and a first_seen timestamp. On each scan we diff the
current findings against this table to classify them:

    NEW       — key not seen before
    WORSENED  — seen before, but severity has increased since
    EXISTING  — seen before at the same-or-lower severity

This is what lets a daily run surface only what changed instead of re-reporting
the same backlog every morning. Stdlib sqlite3 only — zero infra.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from brusky.model import Finding

_DEFAULT_DB = Path.home() / ".brusky" / "state.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    target      TEXT NOT NULL,
    key         TEXT NOT NULL,
    severity    INTEGER NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    PRIMARY KEY (target, key)
);
"""


class State:
    def __init__(self, db_path: Path | None = None) -> None:
        self.path = db_path or _DEFAULT_DB
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> State:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def classify(self, target: str, findings: list[Finding], now: str) -> None:
        """Set `status` and `first_seen` on each finding by diffing against history.

        Mutates the findings in place. Does NOT persist — call `record()` after
        the report is produced so a failed run doesn't poison the baseline.
        """
        rows = {
            r["key"]: r
            for r in self._conn.execute(
                "SELECT key, severity, first_seen FROM findings WHERE target = ?", (target,)
            )
        }
        for f in findings:
            prior = rows.get(f.key)
            if prior is None:
                f.status = "NEW"
                f.first_seen = now
            elif int(f.severity) > prior["severity"]:
                f.status = "WORSENED"
                f.first_seen = prior["first_seen"]
            else:
                f.status = "EXISTING"
                f.first_seen = prior["first_seen"]

    def record(self, target: str, findings: list[Finding], now: str) -> None:
        """Persist the current findings as the new baseline."""
        for f in findings:
            self._conn.execute(
                """
                INSERT INTO findings (target, key, severity, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(target, key) DO UPDATE SET
                    severity   = MAX(severity, excluded.severity),
                    last_seen  = excluded.last_seen
                """,
                (target, f.key, int(f.severity), f.first_seen or now, now),
            )
        self._conn.commit()
