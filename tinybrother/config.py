"""Configuration loading (YAML)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

DEFAULT_CHANNELS = [
    "Security",
    "System",
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
    "Windows PowerShell",
]


@dataclass
class Config:
    channels: list[str] = field(default_factory=lambda: list(DEFAULT_CHANNELS))
    rule_dirs: list[Path] = field(
        default_factory=lambda: [Path("rules/sigma"), Path("rules/custom")]
    )
    database: Path = Path("data/tinybrother.db")
    dashboard_host: str = "127.0.0.1"
    dashboard_port: int = 8765
    min_severity: str = "low"


def load_config(path: str | Path | None) -> Config:
    """Load a YAML config file, falling back to defaults for missing keys."""
    cfg = Config()
    if path is None or not Path(path).exists():
        return cfg
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if "channels" in data:
        cfg.channels = list(data["channels"])
    if "rule_dirs" in data:
        cfg.rule_dirs = [Path(p) for p in data["rule_dirs"]]
    if "database" in data:
        cfg.database = Path(data["database"])
    dash = data.get("dashboard", {})
    cfg.dashboard_host = dash.get("host", cfg.dashboard_host)
    cfg.dashboard_port = int(dash.get("port", cfg.dashboard_port))
    cfg.min_severity = data.get("min_severity", cfg.min_severity)
    return cfg
