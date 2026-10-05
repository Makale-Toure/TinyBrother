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
CREATE TABLE IF NOT EXISTS sensor_status (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    started_at    TEXT NOT NULL,
    heartbeat_at  TEXT NOT NULL,
    stopped_at    TEXT,
    pid           INTEGER,
    hostname      TEXT,
    is_admin      INTEGER,
    rules_loaded  INTEGER,
    events_total  INTEGER NOT NULL DEFAULT 0,
    alerts_total  INTEGER NOT NULL DEFAULT 0,
    last_event_at TEXT,
    channels_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);
"""

# columns added after v0.1, applied to existing databases by `connect`
MIGRATIONS = {
    "alerts": {
        "tactics": "TEXT",
        "description": "TEXT",
        "status": "TEXT NOT NULL DEFAULT 'new'",
        "rule_path": "TEXT",
    },
}

ALERT_STATUSES = ("new", "acknowledged", "closed", "false_positive")


def connect(path: str | Path, check_same_thread: bool = True) -> sqlite3.Connection:
    """Open (and initialise / migrate if needed) the TinyBrother database."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=check_same_thread)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    for table, columns in MIGRATIONS.items():
        existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
        for name, ddl in columns.items():
            if name not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)")
    conn.commit()
    return conn


def to_utc_iso(dt) -> str:
    """Fixed-width UTC ISO string, so text comparison == chronological order."""
    from datetime import timezone

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def insert_event(conn: sqlite3.Connection, event) -> int:
    """Store an event and return its row id."""
    import json

    cur = conn.execute(
        "INSERT INTO events (timestamp, channel, event_id, computer, record_id, fields_json) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            to_utc_iso(event.timestamp),
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
        "INSERT INTO alerts (created_at, rule_id, rule_title, severity, techniques, tactics, "
        "description, rule_path, event_ref) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            to_utc_iso(alert.event.timestamp),
            alert.rule_id,
            alert.rule_title,
            alert.severity.value,
            json.dumps([t.technique_id for t in alert.techniques]),
            json.dumps(sorted({ta for t in alert.techniques for ta in t.tactics})),
            alert.description,
            alert.rule_path,
            event_row,
        ),
    )
    return int(cur.lastrowid)


def write_sensor_status(conn: sqlite3.Connection, status: dict) -> None:
    """Upsert the single row describing the running `watch` sensor."""
    import json

    conn.execute(
        "INSERT INTO sensor_status (id, started_at, heartbeat_at, stopped_at, pid, hostname, "
        "is_admin, rules_loaded, events_total, alerts_total, last_event_at, channels_json) "
        "VALUES (1, :started_at, :heartbeat_at, :stopped_at, :pid, :hostname, :is_admin, "
        ":rules_loaded, :events_total, :alerts_total, :last_event_at, :channels_json) "
        "ON CONFLICT(id) DO UPDATE SET started_at=excluded.started_at, "
        "heartbeat_at=excluded.heartbeat_at, stopped_at=excluded.stopped_at, pid=excluded.pid, "
        "hostname=excluded.hostname, is_admin=excluded.is_admin, "
        "rules_loaded=excluded.rules_loaded, events_total=excluded.events_total, "
        "alerts_total=excluded.alerts_total, last_event_at=excluded.last_event_at, "
        "channels_json=excluded.channels_json",
        {**status, "channels_json": json.dumps(status.get("channels", []))},
    )
    conn.commit()


def save_alerts(conn: sqlite3.Connection, alerts) -> None:
    """Store the triggering event once, then every alert pointing to it."""
    if not alerts:
        return
    event_row = insert_event(conn, alerts[0].event)
    for alert in alerts:
        insert_alert(conn, alert, event_row)
    conn.commit()
