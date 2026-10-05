"""Health of the live sensor (`tinybrother watch`), published to the database.

The dashboard runs in another process: it reads this heartbeat to tell whether
monitoring is running, which channels are readable and how many events were
analysed, so an empty alert list can be told apart from a stopped sensor.
"""

from __future__ import annotations

import os
import socket
import sys
import time
from collections import Counter
from datetime import datetime, timezone

from tinybrother.storage.db import to_utc_iso, write_sensor_status


def is_admin() -> bool | None:
    if sys.platform != "win32":
        return None
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return None


class SensorStatus:
    def __init__(self, conn, channels: list[str], rules_loaded: int, interval: float = 5.0) -> None:
        self.conn = conn
        self.channels = channels
        self.rules_loaded = rules_loaded
        self.interval = interval
        self.started_at = datetime.now(timezone.utc)
        self.events: Counter = Counter()
        self.last_event: dict[str, datetime] = {}
        self.alerts = 0
        self.channel_status: dict[str, str] = {}
        self._last_write = 0.0
        self.admin = is_admin()

    def record_event(self, channel: str, timestamp: datetime) -> None:
        self.events[channel] += 1
        self.last_event[channel] = timestamp

    def record_alerts(self, n: int) -> None:
        self.alerts += n

    def snapshot(self, stopped: bool = False) -> dict:
        now = datetime.now(timezone.utc)
        last = max(self.last_event.values(), default=None)
        return {
            "started_at": to_utc_iso(self.started_at),
            "heartbeat_at": to_utc_iso(now),
            "stopped_at": to_utc_iso(now) if stopped else None,
            "pid": os.getpid(),
            "hostname": socket.gethostname(),
            "is_admin": None if self.admin is None else int(self.admin),
            "rules_loaded": self.rules_loaded,
            "events_total": sum(self.events.values()),
            "alerts_total": self.alerts,
            "last_event_at": to_utc_iso(last) if last else None,
            "channels": [
                {
                    "name": ch,
                    "status": self.channel_status.get(ch, "pending"),
                    "events": self.events.get(ch, 0),
                    "last_event_at": to_utc_iso(self.last_event[ch]) if ch in self.last_event else None,
                }
                for ch in self.channels
            ],
        }

    def heartbeat(self, force: bool = False) -> None:
        if force or time.monotonic() - self._last_write >= self.interval:
            write_sensor_status(self.conn, self.snapshot())
            self._last_write = time.monotonic()

    def stop(self) -> None:
        write_sensor_status(self.conn, self.snapshot(stopped=True))
