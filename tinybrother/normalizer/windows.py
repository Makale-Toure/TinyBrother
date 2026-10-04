"""Windows event XML -> Event normaliser.

Rules of thumb:
- keep Windows/Sysmon field names as-is (Sigma rules reference them directly);
- flatten <EventData><Data Name="X">value</Data> into fields["X"] = value;
- parse <System> into timestamp, channel, event_id, computer, record_id.
"""

from __future__ import annotations

from tinybrother.models import Event


def from_xml(xml: str) -> Event:
    raise NotImplementedError("milestone 1")
