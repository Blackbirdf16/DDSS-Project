from __future__ import annotations
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional


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


@dataclass
class RateLimiterRedis:
    """Redis-backed sliding-window rate limiter for distributed deployments.

    Uses Redis lists per subject to store timestamps and enforces a max events per minute.
    """
    max_per_minute: int
    redis_url: Optional[str] = None
    _client: any = field(init=False, repr=False)

    def __post_init__(self):
        url = self.redis_url or __import__("os").getenv("FAIRRIDE_REDIS_URL", "redis://localhost:6379/0")
        try:
            import redis
            self._client = redis.from_url(url, decode_responses=True)
            self._client.ping()
        except Exception as e:
            raise RuntimeError(f"RateLimiterRedis init failed: {e}")

    def allow(self, subject: str, now: float | None = None) -> bool:
        if now is None:
            now = time.time()
        window_start = now - 60.0
        key = f"rl:{subject}"
        pipe = self._client.pipeline()
        try:
            # Remove old timestamps
            # Fetch list and trim in Lua for atomicity
            script = """
            local key = KEYS[1]
            local window_start = tonumber(ARGV[1])
            local max_per_minute = tonumber(ARGV[2])
            local now = tonumber(ARGV[3])
            -- Remove old entries from the head
            local len = redis.call('LLEN', key)
            for i=1,len do
              local ts = redis.call('LINDEX', key, 0)
              if not ts then break end
              if tonumber(ts) < window_start then
                redis.call('LPOP', key)
              else
                break
              end
            end
            local current = redis.call('LLEN', key)
            if current >= max_per_minute then
              return 0
            end
            redis.call('RPUSH', key, tostring(now))
            -- Optionally set TTL to prevent infinite growth
            redis.call('EXPIRE', key, 120)
            return 1
            """
            allow_fn = self._client.register_script(script)
            res = allow_fn(keys=[key], args=[str(window_start), str(self.max_per_minute), str(now)])
            return bool(int(res))
        except Exception:
            # Fallback to deny on Redis errors to be safe
            return False
