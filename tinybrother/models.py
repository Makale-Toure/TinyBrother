"""Core data models shared by every TinyBrother component."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Alert severity, aligned with Sigma's `level` field."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Event:
    """A normalised host event.

    `fields` holds the flattened event data (e.g. `Image`, `CommandLine`,
    `TargetUserName`) using the original Windows/Sysmon field names, which is
    what Sigma rules expect. `raw` keeps the untouched record for forensics.
    """

    timestamp: datetime
    channel: str  # e.g. "Security", "Microsoft-Windows-Sysmon/Operational"
    event_id: int
    computer: str
    fields: dict[str, Any] = field(default_factory=dict)
    record_id: int | None = None
    provider: str | None = None
    raw: str | None = None


@dataclass
class AttackTechnique:
    """A MITRE ATT&CK technique referenced by a rule (e.g. T1059.001)."""

    technique_id: str
    name: str | None = None
    tactics: list[str] = field(default_factory=list)


@dataclass
class Alert:
    """A detection: one event matched by one rule."""

    rule_id: str
    rule_title: str
    severity: Severity
    event: Event
    techniques: list[AttackTechnique] = field(default_factory=list)
    description: str | None = None
    created_at: datetime = field(default_factory=datetime.now)
