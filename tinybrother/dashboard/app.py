"""FastAPI dashboard, bound to localhost only.

Security notes (see docs/architecture.md):
- the server listens on 127.0.0.1 and rejects any other Host header, which
  blocks DNS-rebinding attacks from a malicious web page;
- the only write endpoint (alert status) requires a JSON body, so a cross-site
  form cannot trigger it without a CORS preflight, which is never granted.
"""

from __future__ import annotations

import logging
import threading
from collections import Counter
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from tinybrother import __version__
from tinybrother.attack.mapping import (
    TACTICS,
    attack_data,
    tactics_for,
    tactics_from_tags,
    techniques_from_tags,
)
from tinybrother.config import Config
from tinybrother.storage import queries
from tinybrother.storage.db import ALERT_STATUSES, connect

log = logging.getLogger(__name__)
STATIC = Path(__file__).parent / "static"
RANGES = {"1h": 1, "24h": 24, "7d": 24 * 7, "30d": 24 * 30, "all": None}


class StatusUpdate(BaseModel):
    status: str


class RuleCoverage:
    """ATT&CK coverage of the loaded rule set, computed in the background."""

    def __init__(self, cfg: Config) -> None:
        self.ready = False
        self.rules = 0
        self.by_tactic: dict[str, Counter] = {}
        threading.Thread(target=self._load, args=(cfg,), daemon=True).start()

    def _load(self, cfg: Config) -> None:
        try:
            from tinybrother.engine.engine import DetectionEngine

            engine = DetectionEngine.from_dirs(cfg.rule_dirs, min_level=cfg.min_severity)
            by_tactic: dict[str, Counter] = {}
            for cr in engine.rules:
                rule_tactics = tactics_from_tags(cr.rule.tags)
                for tech in techniques_from_tags(cr.rule.tags):
                    for ta in tactics_for(tech.technique_id, rule_tactics):
                        by_tactic.setdefault(ta, Counter())[tech.technique_id] += 1
            self.by_tactic = by_tactic
            self.rules = engine.report.loaded
        except Exception:
            log.exception("could not compute rule coverage")
        finally:
            self.ready = True


def _hours(range_: str) -> float | None:
    if range_ not in RANGES:
        raise HTTPException(400, f"range must be one of {list(RANGES)}")
    return RANGES[range_]


def create_app(cfg: Config, with_coverage: bool = True) -> FastAPI:
    app = FastAPI(title="TinyBrother", version=__version__, docs_url="/api/docs", redoc_url=None)
    app.add_middleware(
        TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "testserver"]
    )
    coverage = RuleCoverage(cfg) if with_coverage else None

    def db():
        return connect(cfg.database, check_same_thread=False)

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(STATIC / "index.html")

    @app.get("/api/health")
    def health() -> dict:
        return {
            "status": "ok",
            "version": __version__,
            "database": str(cfg.database),
            "rules_loaded": coverage.rules if coverage and coverage.ready else None,
        }

    @app.get("/api/status")
    def sensor() -> dict:
        """Is live monitoring running? Which channels are readable?"""
        with db() as conn:
            return queries.sensor_status(conn)

    @app.get("/api/stats")
    def stats(range: str = "24h") -> dict:
        with db() as conn:
            return queries.stats(conn, _hours(range))

    @app.get("/api/alerts")
    def alerts(
        range: str = "24h",
        severity: list[str] = Query(default=[]),  # noqa: B008
        status: str | None = None,
        q: str | None = None,
        technique: str | None = None,
        tactic: str | None = None,
        limit: int = Query(50, ge=1, le=500),
        offset: int = Query(0, ge=0),
    ) -> dict:
        with db() as conn:
            return queries.list_alerts(
                conn, _hours(range), severity or None, status, q, technique, tactic, limit, offset
            )

    @app.get("/api/alerts/{alert_id}")
    def alert(alert_id: int) -> dict:
        with db() as conn:
            found = queries.get_alert(conn, alert_id)
        if found is None:
            raise HTTPException(404, "alert not found")
        return found

    @app.patch("/api/alerts/{alert_id}")
    def update_alert(alert_id: int, body: StatusUpdate) -> dict:
        if body.status not in ALERT_STATUSES:
            raise HTTPException(400, f"status must be one of {list(ALERT_STATUSES)}")
        with db() as conn:
            if not queries.set_status(conn, alert_id, body.status):
                raise HTTPException(404, "alert not found")
        return {"id": alert_id, "status": body.status}

    @app.get("/api/techniques")
    def techniques() -> dict:
        """ATT&CK names and short descriptions, fetched once by the dashboard."""
        return attack_data()

    @app.get("/api/attack")
    def attack(range: str = "24h") -> dict:
        with db() as conn:
            hits = queries.attack_matrix(conn, _hours(range))
        cov = coverage.by_tactic if coverage and coverage.ready else {}
        tactics = []
        for ta in TACTICS + sorted(set(hits) - set(TACTICS)):
            techs = set(hits.get(ta, {})) | set(cov.get(ta, {}))
            if not techs:
                continue
            tactics.append({
                "id": ta,
                "techniques": sorted(
                    ({"id": t, "alerts": hits.get(ta, Counter()).get(t, 0),
                      "rules": cov.get(ta, Counter()).get(t, 0)} for t in techs),
                    key=lambda x: (-x["alerts"], -x["rules"], x["id"]),
                ),
            })
        return {"coverage_ready": bool(coverage and coverage.ready), "tactics": tactics}

    app.mount("/static", StaticFiles(directory=STATIC), name="static")
    return app


def run(cfg: Config, open_browser: bool = False) -> None:
    import uvicorn

    url = f"http://{cfg.dashboard_host}:{cfg.dashboard_port}"
    if cfg.dashboard_host not in ("127.0.0.1", "localhost"):
        log.warning("dashboard bound to %s: it is reachable from your network", cfg.dashboard_host)
    if open_browser:
        import webbrowser

        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    log.info("dashboard on %s (Ctrl+C to stop)", url)
    uvicorn.run(create_app(cfg), host=cfg.dashboard_host, port=cfg.dashboard_port, log_level="warning")
