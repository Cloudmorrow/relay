"""Counting attempts, in memory.

A limit here is "at most N in the last W seconds" for a key (an address, a
cloud, a phone waiting to be registered). The counts live in the process
and are lost on restart, which is fine: they slow down guessing and
squatting, they are not an audit log.

The table is bounded, so a flood of distinct keys (spoofed or rotating
addresses) cannot grow it without end: past the bound, the keys least
recently touched are forgotten first.
"""

from __future__ import annotations

import time
from collections import OrderedDict, deque


class RateLimiter:
    def __init__(self, limit: int, window: float, max_keys: int = 100_000):
        self.limit = limit
        self.window = window
        self.max_keys = max_keys
        self._hits: OrderedDict[str, deque[float]] = OrderedDict()

    def _recent(self, key: str, now: float) -> deque[float]:
        hits = self._hits.get(key)
        if hits is None:
            hits = self._hits[key] = deque()
            while len(self._hits) > self.max_keys:
                self._hits.popitem(last=False)
        else:
            self._hits.move_to_end(key)
        while hits and hits[0] <= now - self.window:
            hits.popleft()
        return hits

    def allow(self, key: str) -> bool:
        """Count one attempt for `key`, and say whether it is within the
        limit. Refused attempts are not counted, so waiting out the window
        always works.
        """
        now = time.monotonic()
        hits = self._recent(key, now)
        if len(hits) >= self.limit:
            return False
        hits.append(now)
        return True

    def blocked(self, key: str) -> bool:
        """Whether `key` is over the limit, without counting anything."""
        return len(self._recent(key, time.monotonic())) >= self.limit

    def hit(self, key: str) -> None:
        """Count an attempt without asking (a failure, counted after it)."""
        self._recent(key, time.monotonic()).append(time.monotonic())
