from __future__ import annotations
import time
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class RateLimiter:
    """
    Simple sliding-window rate limiter.
    Educational / demo. In production you’d use Redis, etc.
    """
    max_per_minute: int
    _events: Dict[str, List[float]] = field(default_factory=dict)

    def allow(self, subject: str, now: float | None = None) -> bool:
        if now is None:
            now = time.time()
        window_start = now - 60.0
        events = self._events.setdefault(subject, [])
        # Drop old
        while events and events[0] < window_start:
            events.pop(0)
        if len(events) >= self.max_per_minute:
            return False
        events.append(now)
        return True
