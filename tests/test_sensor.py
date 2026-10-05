from datetime import datetime, timedelta, timezone

from tinybrother.sensor import SensorStatus
from tinybrother.storage.db import connect
from tinybrother.storage.queries import sensor_status

CHANNELS = ["Security", "Microsoft-Windows-Sysmon/Operational"]


def make(tmp_path):
    conn = connect(tmp_path / "tb.db")
    s = SensorStatus(conn, CHANNELS, rules_loaded=10)
    s.admin = True
    s.channel_status.update({"Security": "ok", "Microsoft-Windows-Sysmon/Operational": "ok"})
    return conn, s


def test_never_started(tmp_path):
    conn = connect(tmp_path / "tb.db")
    st = sensor_status(conn)
    assert st["state"] == "never"
    assert st["warnings"][0]["code"] == "never_started"


def test_running_with_counters(tmp_path):
    conn, s = make(tmp_path)
    now = datetime.now(timezone.utc)
    s.record_event("Security", now)
    s.record_event("Security", now)
    s.record_alerts(1)
    s.heartbeat(force=True)
    st = sensor_status(conn)
    assert st["state"] == "running"
    assert st["events_total"] == 2 and st["alerts_total"] == 1
    sec = next(c for c in st["channels"] if c["name"] == "Security")
    assert sec["events"] == 2 and sec["status"] == "ok"
    assert st["warnings"] == []


def test_stale_and_stopped(tmp_path):
    conn, s = make(tmp_path)
    s.heartbeat(force=True)
    later = datetime.now(timezone.utc) + timedelta(minutes=5)
    assert sensor_status(conn, now=later)["state"] == "stale"
    s.stop()
    st = sensor_status(conn)
    assert st["state"] == "stopped"
    assert st["warnings"][0]["code"] == "not_running"


def test_warnings_for_missing_sysmon_and_admin(tmp_path):
    conn, s = make(tmp_path)
    s.admin = False
    s.channel_status.update({"Security": "access_denied",
                             "Microsoft-Windows-Sysmon/Operational": "not_found"})
    s.heartbeat(force=True)
    codes = {w["code"] for w in sensor_status(conn)["warnings"]}
    assert codes == {"sysmon_missing", "not_admin"}
