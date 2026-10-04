"""Windows event XML -> Event normaliser.

Rules:
- keep Windows/Sysmon field names as-is (Sigma rules reference them directly);
- flatten <EventData><Data Name="X">value</Data> into fields["X"] = value;
- unnamed <Data> elements (classic providers) become Data_0, Data_1, ...;
- <UserData> leaf elements are flattened by tag name (e.g. log-cleared events);
- <System> gives timestamp, channel, event_id, computer, record_id, provider.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from tinybrother.models import Event


class NormalizationError(ValueError):
    """Raised when an XML record cannot be turned into an Event."""


_NS_RE = re.compile(r"^\{[^}]*\}")
_FRACTION_RE = re.compile(r"\.(\d+)")


def _local(tag: str) -> str:
    """Strip the XML namespace: '{ns}EventID' -> 'EventID'."""
    return _NS_RE.sub("", tag)


def _child(parent: ET.Element, name: str) -> ET.Element | None:
    for el in parent:
        if _local(el.tag) == name:
            return el
    return None


def parse_timestamp(value: str) -> datetime:
    """Parse Windows SystemTime ('2026-10-04T10:00:00.1234567Z') as aware UTC."""
    v = value.strip().replace("Z", "+00:00")
    # Windows uses 7 fractional digits, Python accepts at most 6
    v = _FRACTION_RE.sub(lambda m: "." + m.group(1)[:6].ljust(6, "0"), v, count=1)
    if " " in v and "T" not in v:
        v = v.replace(" ", "T", 1)
    dt = datetime.fromisoformat(v)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _convert(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    return value if value else None


def from_xml(xml: str) -> Event:
    """Convert one rendered Windows event (XML string) into an Event."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        raise NormalizationError(f"invalid XML: {exc}") from exc

    system = _child(root, "System")
    if system is None:
        raise NormalizationError("missing <System> element")

    provider_el = _child(system, "Provider")
    eid_el = _child(system, "EventID")
    time_el = _child(system, "TimeCreated")
    rec_el = _child(system, "EventRecordID")
    chan_el = _child(system, "Channel")
    comp_el = _child(system, "Computer")

    if eid_el is None or eid_el.text is None:
        raise NormalizationError("missing EventID")
    if time_el is None or "SystemTime" not in time_el.attrib:
        raise NormalizationError("missing TimeCreated/@SystemTime")

    fields: dict[str, str | None] = {}

    event_data = _child(root, "EventData")
    if event_data is not None:
        unnamed = 0
        for data in event_data:
            if _local(data.tag) != "Data":
                continue
            name = data.attrib.get("Name")
            if name:
                fields[name] = _convert(data.text)
            else:
                fields[f"Data_{unnamed}"] = _convert(data.text)
                unnamed += 1

    user_data = _child(root, "UserData")
    if user_data is not None:
        for el in user_data.iter():
            if len(el) == 0 and el is not user_data:
                fields.setdefault(_local(el.tag), _convert(el.text))

    # handy System values that Sigma rules sometimes reference
    fields["EventID"] = eid_el.text.strip()
    if provider_el is not None and provider_el.attrib.get("Name"):
        fields["Provider_Name"] = provider_el.attrib["Name"]

    return Event(
        timestamp=parse_timestamp(time_el.attrib["SystemTime"]),
        channel=(chan_el.text or "").strip() if chan_el is not None else "",
        event_id=int(eid_el.text.strip()),
        computer=(comp_el.text or "").strip() if comp_el is not None else "",
        fields=fields,
        record_id=int(rec_el.text) if rec_el is not None and rec_el.text else None,
        provider=provider_el.attrib.get("Name") if provider_el is not None else None,
        raw=xml,
    )
