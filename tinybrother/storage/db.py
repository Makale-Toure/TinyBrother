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
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    return conn


def insert_event(conn: sqlite3.Connection, event) -> int:
    """Store an event and return its row id."""
    import json

    cur = conn.execute(
        "INSERT INTO events (timestamp, channel, event_id, computer, record_id, fields_json) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            event.timestamp.isoformat(),
            event.channel,
            event.event_id,
            event.computer,
            event.record_id,
            json.dumps(event.fields, ensure_ascii=False),
        ),
    )
    return int(cur.lastrowid)


def insert_alert(conn: sqlite3.Connection, alert, event_row: int | None) -> int:
    import json

    cur = conn.execute(
        "INSERT INTO alerts (created_at, rule_id, rule_title, severity, techniques, event_ref) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            alert.event.timestamp.isoformat(),
            alert.rule_id,
            alert.rule_title,
            alert.severity.value,
            json.dumps([t.technique_id for t in alert.techniques]),
            event_row,
        ),
    )
    return int(cur.lastrowid)


def save_alerts(conn: sqlite3.Connection, alerts) -> None:
    """Store the triggering event once, then every alert pointing to it."""
    if not alerts:
        return
    event_row = insert_event(conn, alerts[0].event)
    for alert in alerts:
        insert_alert(conn, alert, event_row)
    conn.commit()
