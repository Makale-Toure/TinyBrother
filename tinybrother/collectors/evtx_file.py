"""Offline collection from exported .evtx files (works on any OS)."""

from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path

from tinybrother.collectors.base import Collector
from tinybrother.models import Event
from tinybrother.normalizer.windows import from_xml

log = logging.getLogger(__name__)


class EvtxFileCollector(Collector):
    """Replay every record of an .evtx file as normalised events."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.errors = 0

    def events(self) -> Iterator[Event]:
        from Evtx.Evtx import Evtx  # python-evtx

        if not self.path.is_file():
            raise FileNotFoundError(self.path)
        with Evtx(str(self.path)) as evtx:
            for record in evtx.records():
                try:
                    yield from_xml(record.xml())
                except Exception as exc:  # noqa: BLE001 - corrupted records exist
                    self.errors += 1
                    log.debug("skipping record in %s: %s", self.path, exc)
