"""Offline collection from exported .evtx files (works on any OS).

Uses the Rust-based `evtx` package (fast); falls back to the pure-Python
`python-evtx` package if `evtx` is not installed.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path

from tinybrother.collectors.base import Collector
from tinybrother.models import Event
from tinybrother.normalizer.windows import from_xml

log = logging.getLogger(__name__)


def _xml_records(path: Path) -> Iterator[str]:
    try:
        from evtx import PyEvtxParser
    except ImportError:  # pragma: no cover - fallback
        from Evtx.Evtx import Evtx

        with Evtx(str(path)) as log_file:
            for record in log_file.records():
                yield record.xml()
        return
    for record in PyEvtxParser(str(path)).records():
        yield record["data"]


class EvtxFileCollector(Collector):
    """Replay every record of an .evtx file as normalised events."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.errors = 0

    def events(self) -> Iterator[Event]:
        if not self.path.is_file():
            raise FileNotFoundError(self.path)
        for xml in _xml_records(self.path):
            try:
                yield from_xml(xml)
            except Exception as exc:  # noqa: BLE001 - corrupted records exist
                self.errors += 1
                log.debug("skipping record in %s: %s", self.path, exc)
