"""Live collection from the Windows Event Log (Windows only, needs admin).

Planned implementation: `win32evtlog.EvtSubscribe` per channel with a
bookmark so TinyBrother resumes where it stopped after a restart.
"""

from __future__ import annotations

from collections.abc import Iterator

from tinybrother.collectors.base import Collector
from tinybrother.models import Event


class WindowsEventLogCollector(Collector):
    def __init__(self, channels: list[str]) -> None:
        self.channels = channels

    def events(self) -> Iterator[Event]:  # pragma: no cover - Windows only
        raise NotImplementedError("milestone 1")
