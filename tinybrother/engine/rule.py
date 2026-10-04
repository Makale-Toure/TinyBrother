"""In-memory representation of a Sigma rule."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SigmaRule:
    id: str
    title: str
    level: str
    logsource: dict[str, str]
    detection: dict[str, Any]
    tags: list[str] = field(default_factory=list)
    description: str | None = None
    falsepositives: list[str] = field(default_factory=list)
    path: str | None = None
