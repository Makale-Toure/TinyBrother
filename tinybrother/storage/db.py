"""SQLite storage layer."""

from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY,
    timestamp   TEXT NOT NULL,
    channel     TEXT NOT NULL,
    event_id    INTEGER NOT NULL,
    computer    TEXT,
    record_id   INTEGER,
    fields_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY,
    created_at  TEXT NOT NULL,
    rule_id     TEXT NOT NULL,
    rule_title  TEXT NOT NULL,
    severity    TEXT NOT NULL,
    techniques  TEXT,
    event_ref   INTEGER REFERENCES events(id)
);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);
"""


def connect(path: str | Path) -> sqlite3.Connection:
    """Open (and initialise if needed) the TinyBrother database."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn
