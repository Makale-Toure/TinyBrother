"""Collector interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator

from tinybrother.models import Event


class Collector(ABC):
    """A source of normalised events."""

    @abstractmethod
    def events(self) -> Iterator[Event]:
        """Yield events. Live collectors block and yield forever."""
