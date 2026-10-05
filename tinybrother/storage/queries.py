"""Read-side queries used by the dashboard API."""

from __future__ import annotations

import json
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from tinybrother.storage.db import to_utc_iso

SEVERITIES = ["critical", "high", "medium", "low", "informational"]

_SUMMARY_FIELDS = (
    "Image", "CommandLine", "ParentImage", "TargetFilename", "TargetObject",
    "DestinationIp", "DestinationPort", "QueryName", "ScriptBlockText",
    "TargetUserName", "SubjectUserName", "LogonType", "IpAddress", "ServiceName",
    "ThreatName", "Data_0",
)


def summarize(fields: dict, width: int = 160) -> str:
    parts = []
    for key in _SUMMARY_FIELDS:
        v = fields.get(key)
        if v:
            parts.append(f"{key}={v}")
        if len(parts) == 2:
            break
    text = " ".join(parts).replace("\n", " ")
    return text if len(text) <= width else text[: width - 1] + "…"


def parse_ts(value: str) -> datetime:
    v = value.replace("Z", "+00:00")
    dt = datetime.fromisoformat(v)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def time_bounds(conn: sqlite3.Connection, hours: float | None) -> tuple[str | None, str | None]:
    """[start, end) of the requested range; `hours=None` means all data."""
    if hours is None:
        row = conn.execute("SELECT MIN(created_at), MAX(created_at) FROM alerts").fetchone()
        return row[0], None
    start = datetime.now(timezone.utc) - timedelta(hours=hours)
    return to_utc_iso(start), None


def _where(start: str | None, extra: list[str] | None = None) -> tuple[str, list]:
    clauses, params = [], []
    if start:
        clauses.append("a.created_at >= ?")
        params.append(start)
    clauses.extend(extra or [])
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", params


def stats(conn: sqlite3.Connection, hours: float | None) -> dict:
    start, _ = time_bounds(conn, hours)
    where, params = _where(start)
    rows = conn.execute(
        f"SELECT a.created_at, a.severity, a.status, a.rule_title, a.techniques "
        f"FROM alerts a{where} ORDER BY a.created_at",
        params,
    ).fetchall()

    by_sev = Counter(r["severity"] for r in rows)
    open_count = sum(1 for r in rows if r["status"] == "new")
    techniques: Counter = Counter()
    rules: dict[str, dict] = {}
    for r in rows:
        for t in json.loads(r["techniques"] or "[]"):
            techniques[t] += 1
        entry = rules.setdefault(r["rule_title"], {"title": r["rule_title"],
                                                  "severity": r["severity"], "count": 0})
        entry["count"] += 1

    timeline = _timeline(rows, hours)
    return {
        "range_hours": hours,
        "total": len(rows),
        "open": open_count,
        "by_severity": {s: by_sev.get(s, 0) for s in SEVERITIES},
        "distinct_techniques": len(techniques),
        "first_alert": rows[0]["created_at"] if rows else None,
        "last_alert": rows[-1]["created_at"] if rows else None,
        "timeline": timeline,
        "top_rules": sorted(rules.values(), key=lambda r: -r["count"])[:10],
        "top_techniques": [{"id": t, "count": n} for t, n in techniques.most_common(10)],
    }


def _timeline(rows, hours: float | None) -> dict:
    """Bucket alerts by time and severity (~24-60 buckets)."""
    now = datetime.now(timezone.utc)
    if hours is not None:
        end = now
        start = now - timedelta(hours=hours)
    elif rows:
        start, end = parse_ts(rows[0]["created_at"]), parse_ts(rows[-1]["created_at"])
    else:
        return {"bucket_seconds": 3600, "buckets": []}

    span = max((end - start).total_seconds(), 3600)
    steps = [60, 300, 900, 1800, 3600, 3 * 3600, 6 * 3600, 12 * 3600, 86400, 7 * 86400, 30 * 86400]
    size = next((s for s in steps if span / s <= 60), steps[-1])

    def floor(dt: datetime) -> datetime:
        epoch = int(dt.timestamp())
        return datetime.fromtimestamp(epoch - epoch % size, tz=timezone.utc)

    first, last = floor(start), floor(end)
    buckets: dict[datetime, Counter] = defaultdict(Counter)
    for r in rows:
        buckets[floor(parse_ts(r["created_at"]))][r["severity"]] += 1
    out = []
    t = first
    while t <= last:
        c = buckets.get(t, Counter())
        out.append({"t": to_utc_iso(t), **{s: c.get(s, 0) for s in SEVERITIES}})
        t += timedelta(seconds=size)
    return {"bucket_seconds": size, "buckets": out}


def list_alerts(
    conn: sqlite3.Connection,
    hours: float | None,
    severity: list[str] | None = None,
    status: str | None = None,
    q: str | None = None,
    technique: str | None = None,
    tactic: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    start, _ = time_bounds(conn, hours)
    extra, params_extra = [], []
    if severity:
        extra.append(f"a.severity IN ({','.join('?' * len(severity))})")
        params_extra += severity
    if status:
        extra.append("a.status = ?")
        params_extra.append(status)
    if q:
        extra.append("(a.rule_title LIKE ? OR e.fields_json LIKE ?)")
        params_extra += [f"%{q}%", f"%{q}%"]
    if technique:
        extra.append("a.techniques LIKE ?")
        params_extra.append(f'%"{technique}%')
    if tactic:
        extra.append("a.tactics LIKE ?")
        params_extra.append(f'%"{tactic}"%')
    where, params = _where(start, extra)
    params += params_extra
    base = f"FROM alerts a LEFT JOIN events e ON e.id = a.event_ref{where}"
    total = conn.execute(f"SELECT COUNT(*) {base}", params).fetchone()[0]
    rows = conn.execute(
        f"SELECT a.*, e.channel, e.event_id, e.computer, e.fields_json {base} "
        f"ORDER BY a.created_at DESC, a.id DESC LIMIT ? OFFSET ?",
        params + [limit, offset],
    ).fetchall()
    items = []
    for r in rows:
        fields = json.loads(r["fields_json"] or "{}")
        items.append({
            "id": r["id"],
            "created_at": r["created_at"],
            "rule_title": r["rule_title"],
            "severity": r["severity"],
            "status": r["status"],
            "techniques": json.loads(r["techniques"] or "[]"),
            "tactics": json.loads(r["tactics"] or "[]"),
            "channel": r["channel"],
            "event_id": r["event_id"],
            "computer": r["computer"],
            "summary": summarize(fields),
        })
    return {"total": total, "items": items}


def get_alert(conn: sqlite3.Connection, alert_id: int) -> dict | None:
    r = conn.execute(
        "SELECT a.*, e.channel, e.event_id, e.computer, e.record_id, e.timestamp AS event_ts, "
        "e.fields_json FROM alerts a LEFT JOIN events e ON e.id = a.event_ref WHERE a.id = ?",
        (alert_id,),
    ).fetchone()
    if r is None:
        return None
    return {
        "id": r["id"],
        "created_at": r["created_at"],
        "rule_id": r["rule_id"],
        "rule_title": r["rule_title"],
        "rule_path": r["rule_path"],
        "description": r["description"],
        "severity": r["severity"],
        "status": r["status"],
        "techniques": json.loads(r["techniques"] or "[]"),
        "tactics": json.loads(r["tactics"] or "[]"),
        "event": {
            "channel": r["channel"],
            "event_id": r["event_id"],
            "computer": r["computer"],
            "record_id": r["record_id"],
            "timestamp": r["event_ts"],
            "fields": json.loads(r["fields_json"] or "{}"),
        },
    }


def set_status(conn: sqlite3.Connection, alert_id: int, status: str) -> bool:
    cur = conn.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))
    conn.commit()
    return cur.rowcount > 0


def attack_matrix(conn: sqlite3.Connection, hours: float | None) -> dict[str, Counter]:
    """tactic -> Counter(technique -> alert count) for the range."""
    start, _ = time_bounds(conn, hours)
    where, params = _where(start)
    from tinybrother.attack.mapping import tactics_for

    out: dict[str, Counter] = defaultdict(Counter)
    for r in conn.execute(f"SELECT a.techniques, a.tactics FROM alerts a{where}", params):
        rule_tactics = json.loads(r["tactics"] or "[]")
        for t in json.loads(r["techniques"] or "[]"):
            for ta in tactics_for(t, rule_tactics):
                out[ta][t] += 1
    return out


SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
STALE_AFTER_SECONDS = 30


def sensor_status(conn: sqlite3.Connection, now: datetime | None = None) -> dict:
    """State of the `watch` sensor: running, stopped or never started, plus warnings."""
    now = now or datetime.now(timezone.utc)
    r = conn.execute("SELECT * FROM sensor_status WHERE id = 1").fetchone()
    if r is None:
        return {"state": "never", "warnings": [{
            "code": "never_started",
            "message": "Start `tinybrother watch` in an administrator terminal to analyse "
                       "this machine's activity.",
        }]}

    channels = json.loads(r["channels_json"] or "[]")
    age = (now - parse_ts(r["heartbeat_at"])).total_seconds()
    if r["stopped_at"]:
        state = "stopped"
    elif age > STALE_AFTER_SECONDS:
        state = "stale"  # process died without a clean shutdown
    else:
        state = "running"

    warnings = []
    if state != "running":
        warnings.append({
            "code": "not_running",
            "message": "New activity on this machine is not analysed. Start "
                       "`tinybrother watch` in an administrator terminal.",
        })
    by_name = {c["name"]: c for c in channels}
    if by_name.get(SYSMON_CHANNEL, {}).get("status") == "not_found":
        warnings.append({
            "code": "sysmon_missing",
            "message": "Most rules (process, network, registry and file activity) cannot fire "
                       "without it. Install it with `scripts\\install_sysmon.ps1` from an "
                       "administrator terminal.",
        })
    if r["is_admin"] == 0 or any(c["status"] == "access_denied" for c in channels):
        warnings.append({
            "code": "not_admin",
            "message": "The Security log (logons, privilege use, log clearing) cannot be read. "
                       "Restart `tinybrother watch` from an administrator terminal.",
        })

    return {
        "state": state,
        "started_at": r["started_at"],
        "heartbeat_at": r["heartbeat_at"],
        "stopped_at": r["stopped_at"],
        "heartbeat_age_seconds": round(age, 1),
        "hostname": r["hostname"],
        "pid": r["pid"],
        "is_admin": None if r["is_admin"] is None else bool(r["is_admin"]),
        "rules_loaded": r["rules_loaded"],
        "events_total": r["events_total"],
        "alerts_total": r["alerts_total"],
        "last_event_at": r["last_event_at"],
        "channels": channels,
        "warnings": warnings,
    }
