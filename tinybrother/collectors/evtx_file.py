"""Offline collection from exported .evtx files (works on any OS)."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from tinybrother.collectors.base import Collector
from tinybrother.models import Event


class EvtxFileCollector(Collector):
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def events(self) -> Iterator[Event]:
        raise NotImplementedError("milestone 1: parse with python-evtx, then normalise")
