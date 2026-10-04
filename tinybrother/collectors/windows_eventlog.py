"""Live collection from the Windows Event Log (Windows only, needs admin).

Strategy: poll each channel with an XPath query on EventRecordID, which is
monotonic per channel. The last record ID seen per channel is saved in a
small JSON state file, so a restart resumes exactly where it stopped:
no event lost, none processed twice.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Iterator
from pathlib import Path

from tinybrother.collectors.base import Collector
from tinybrother.models import Event
from tinybrother.normalizer.windows import NormalizationError, from_xml

log = logging.getLogger(__name__)

ERROR_NO_MORE_ITEMS = 259
ERROR_EVT_CHANNEL_NOT_FOUND = 15007
ERROR_ACCESS_DENIED = 5
BATCH = 64


class WindowsEventLogCollector(Collector):
    def __init__(
        self,
        channels: list[str],
        state_file: str | Path = "data/state.json",
        poll_interval: float = 1.0,
        from_start: bool = False,
    ) -> None:
        self.channels = channels
        self.state_file = Path(state_file)
        self.poll_interval = poll_interval
        self.from_start = from_start
        self.state: dict[str, int] = self._load_state()

    # ---------- state ----------
    def _load_state(self) -> dict[str, int]:
        try:
            return {k: int(v) for k, v in json.loads(self.state_file.read_text()).items()}
        except (FileNotFoundError, ValueError):
            return {}

    def _save_state(self) -> None:
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.state_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.state, indent=2))
        tmp.replace(self.state_file)

    # ---------- win32 helpers ----------
    @staticmethod
    def _latest_record_id(channel: str) -> int:
        import win32evtlog

        flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection
        handle = win32evtlog.EvtQuery(channel, flags, "*")
        events = win32evtlog.EvtNext(handle, 1)
        if not events:
            return 0
        return from_xml(win32evtlog.EvtRender(events[0], win32evtlog.EvtRenderEventXml)).record_id or 0

    @staticmethod
    def _read_after(channel: str, last_id: int) -> Iterator[str]:
        import pywintypes
        import win32evtlog

        flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection
        query = f"*[System[EventRecordID > {last_id}]]"
        handle = win32evtlog.EvtQuery(channel, flags, query)
        while True:
            try:
                events = win32evtlog.EvtNext(handle, BATCH)
            except pywintypes.error as exc:
                if exc.winerror == ERROR_NO_MORE_ITEMS:
                    return
                raise
            if not events:
                return
            for evt in events:
                yield win32evtlog.EvtRender(evt, win32evtlog.EvtRenderEventXml)

    # ---------- main loop ----------
    def _init_channels(self) -> list[str]:
        import pywintypes

        active = []
        for ch in self.channels:
            try:
                if ch not in self.state:
                    self.state[ch] = 0 if self.from_start else self._latest_record_id(ch)
                active.append(ch)
            except pywintypes.error as exc:
                if exc.winerror == ERROR_EVT_CHANNEL_NOT_FOUND:
                    log.warning("channel not found, skipped: %s (is Sysmon installed?)", ch)
                elif exc.winerror == ERROR_ACCESS_DENIED:
                    log.warning("access denied to %s: run TinyBrother as administrator", ch)
                else:
                    log.warning("cannot open %s: %s", ch, exc)
        self._save_state()
        return active

    def events(self) -> Iterator[Event]:  # pragma: no cover - Windows only
        channels = self._init_channels()
        if not channels:
            raise RuntimeError("no readable channel; check admin rights and config")
        log.info("watching %d channel(s): %s", len(channels), ", ".join(channels))
        while True:
            before = dict(self.state)
            for ch in channels:
                for xml in self._read_after(ch, self.state[ch]):
                    try:
                        event = from_xml(xml)
                    except NormalizationError as exc:
                        log.debug("bad record on %s: %s", ch, exc)
                        continue
                    if event.record_id:
                        self.state[ch] = max(self.state[ch], event.record_id)
                    yield event
            if self.state != before:
                self._save_state()
            time.sleep(self.poll_interval)
