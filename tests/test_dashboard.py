from pathlib import Path

import pytest

from tinybrother.config import Config
from tinybrother.engine.engine import DetectionEngine
from tinybrother.normalizer.windows import from_xml
from tinybrother.storage.db import connect, save_alerts

pytest.importorskip("httpx")
from fastapi.testclient import TestClient

from tinybrother.dashboard.app import create_app

ROOT = Path(__file__).resolve().parent.parent
FIX = Path(__file__).parent / "fixtures"


@pytest.fixture()
def client(tmp_path):
    cfg = Config(database=tmp_path / "tb.db", rule_dirs=[ROOT / "rules" / "custom"])
    engine = DetectionEngine.from_dirs(cfg.rule_dirs)
    event = from_xml((FIX / "sysmon_1.xml").read_text(encoding="utf-8"))
    conn = connect(cfg.database)
    save_alerts(conn, engine.evaluate(event))
    conn.close()
    return TestClient(create_app(cfg, with_coverage=False))


def test_stats(client):
    s = client.get("/api/stats?range=all").json()
    assert s["total"] == 1
    assert s["by_severity"]["high"] == 1
    assert s["distinct_techniques"] == 2
    assert s["timeline"]["buckets"]


def test_list_filter_and_detail(client):
    items = client.get("/api/alerts?range=all&severity=high").json()["items"]
    assert len(items) == 1 and "powershell" in items[0]["summary"].lower()
    assert client.get("/api/alerts?range=all&severity=low").json()["total"] == 0
    assert client.get("/api/alerts?range=all&technique=T1059.001").json()["total"] == 1
    assert client.get("/api/alerts?range=all&q=nothing-like-this").json()["total"] == 0

    detail = client.get(f"/api/alerts/{items[0]['id']}").json()
    assert detail["event"]["fields"]["CommandLine"].startswith("powershell.exe")
    assert "execution" in detail["tactics"]


def test_triage(client):
    alert_id = client.get("/api/alerts?range=all").json()["items"][0]["id"]
    assert client.patch(f"/api/alerts/{alert_id}", json={"status": "false_positive"}).status_code == 200
    assert client.get(f"/api/alerts/{alert_id}").json()["status"] == "false_positive"
    assert client.patch(f"/api/alerts/{alert_id}", json={"status": "hacked"}).status_code == 400
    assert client.patch("/api/alerts/999", json={"status": "closed"}).status_code == 404


def test_attack_matrix(client):
    tactics = {t["id"]: t for t in client.get("/api/attack?range=all").json()["tactics"]}
    assert any(x["id"] == "T1059.001" and x["alerts"] == 1 for x in tactics["execution"]["techniques"])


def test_rejects_foreign_host_header(client):
    assert client.get("/api/health", headers={"host": "evil.example"}).status_code == 400


def test_invalid_range(client):
    assert client.get("/api/stats?range=forever").status_code == 400


def test_index_served(client):
    r = client.get("/")
    assert r.status_code == 200 and "TinyBrother" in r.text


def test_status_endpoint(client):
    st = client.get("/api/status").json()
    assert st["state"] == "never"
