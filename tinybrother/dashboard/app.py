"""FastAPI dashboard, bound to localhost only."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse

from tinybrother import __version__
from tinybrother.config import Config

STATIC = Path(__file__).parent / "static"


def create_app(cfg: Config) -> FastAPI:
    app = FastAPI(title="TinyBrother", version=__version__)

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(STATIC / "index.html")

    @app.get("/api/health")
    def health() -> dict:
        return {"status": "ok", "version": __version__}

    # milestone 3: /api/alerts, /api/stats, /api/attack-coverage
    return app


def run(cfg: Config) -> None:
    import uvicorn

    uvicorn.run(create_app(cfg), host=cfg.dashboard_host, port=cfg.dashboard_port)
