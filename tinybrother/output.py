"""Human-readable and JSON rendering of events."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable

from tinybrother.models import Event

# fields worth showing first, in order, when present
_KEY_FIELDS = (
    "Image", "CommandLine", "ParentImage", "TargetFilename", "TargetObject",
    "DestinationIp", "DestinationPort", "QueryName", "ScriptBlockText",
    "TargetUserName", "SubjectUserName", "LogonType", "IpAddress", "ServiceName",
    "ThreatName", "Data_0",
)

_SHORT_CHANNEL = {
    "Microsoft-Windows-Sysmon/Operational": "Sysmon",
    "Microsoft-Windows-PowerShell/Operational": "PowerShell",
    "Microsoft-Windows-Windows Defender/Operational": "Defender",
}


def short_channel(channel: str) -> str:
    return _SHORT_CHANNEL.get(channel, channel)


def summary(event: Event, width: int = 140) -> str:
    parts = []
    for key in _KEY_FIELDS:
        val = event.fields.get(key)
        if val:
            parts.append(f"{key}={val}")
        if len(parts) == 3:
            break
    text = " ".join(parts).replace("\n", " ")
    return text if len(text) <= width else text[: width - 1] + "…"


def format_line(event: Event) -> str:
    ts = event.timestamp.strftime("%Y-%m-%d %H:%M:%S")
    return f"{ts}  {short_channel(event.channel):<11} {event.event_id:>5}  {summary(event)}"


def to_json(event: Event) -> str:
    return json.dumps(
        {
            "timestamp": event.timestamp.isoformat(),
            "channel": event.channel,
            "event_id": event.event_id,
            "computer": event.computer,
            "record_id": event.record_id,
            "provider": event.provider,
            "fields": event.fields,
        },
        ensure_ascii=False,
    )


def stats_table(counter: Counter, top: int = 15) -> str:
    lines = [f"{'channel':<45} {'EventID':>7} {'count':>8}", "-" * 62]
    for (channel, eid), n in counter.most_common(top):
        lines.append(f"{channel:<45} {eid:>7} {n:>8}")
    return "\n".join(lines)


def count(events: Iterable[Event]) -> Counter:
    return Counter((e.channel, e.event_id) for e in events)


_SEV_TAG = {
    "critical": "CRIT",
    "high": "HIGH",
    "medium": "MED ",
    "low": "LOW ",
    "informational": "INFO",
}


def format_alert(alert) -> str:
    ev = alert.event
    ts = ev.timestamp.strftime("%Y-%m-%d %H:%M:%S")
    techs = ", ".join(
        f"{t.technique_id} {t.name}" if t.name and t.name != t.technique_id else t.technique_id
        for t in alert.techniques
    ) or "-"
    head = f"{ts}  [{_SEV_TAG.get(alert.severity.value, '????')}] {alert.rule_title}  ({techs})"
    return f"{head}\n    {short_channel(ev.channel)} {ev.event_id}  {summary(ev)}"


def alert_to_json(alert) -> str:
    return json.dumps(
        {
            "timestamp": alert.event.timestamp.isoformat(),
            "rule_id": alert.rule_id,
            "rule_title": alert.rule_title,
            "severity": alert.severity.value,
            "techniques": [t.technique_id for t in alert.techniques],
            "tactics": sorted({ta for t in alert.techniques for ta in t.tactics}),
            "channel": alert.event.channel,
            "event_id": alert.event.event_id,
            "record_id": alert.event.record_id,
            "fields": alert.event.fields,
        },
        ensure_ascii=False,
    )
