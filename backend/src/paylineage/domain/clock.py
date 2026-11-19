"""One time source for the whole service, injectable for tests. UTC only."""

from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta
from typing import Protocol


class Clock(Protocol):
    def now(self) -> datetime: ...


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


class FrozenClock:
    """Test clock. Thread safe, moves only when told to."""

    def __init__(self, start: datetime) -> None:
        if start.tzinfo is None:
            raise ValueError("FrozenClock needs an aware UTC datetime")
        self._now = start
        self._lock = threading.Lock()

    def now(self) -> datetime:
        with self._lock:
            return self._now

    def advance(self, delta: timedelta) -> None:
        with self._lock:
            self._now += delta

    def set(self, when: datetime) -> None:
        with self._lock:
            self._now = when


def to_ms(dt: datetime) -> int:
    if dt.tzinfo is None:
        raise ValueError("naive datetime")
    return int(dt.timestamp() * 1000)


def from_ms(ms: int) -> datetime:
    return datetime.fromtimestamp(ms / 1000, tz=UTC)
