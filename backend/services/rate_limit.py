"""Shared rate limit backend with a safe single-process fallback."""

import threading
import time

from config import settings


class RateLimitBackend:
    def __init__(self):
        self._local = {}
        self._lock = threading.Lock()
        self._redis = None
        if settings.REDIS_URL:
            try:
                import redis
                client = redis.Redis.from_url(settings.REDIS_URL, socket_connect_timeout=1, socket_timeout=1)
                client.ping()
                self._redis = client
            except Exception:
                self._redis = None

    @property
    def distributed(self) -> bool:
        return self._redis is not None

    def hit(self, key: str, limit: int, window_seconds: int = 60) -> tuple[bool, int, int]:
        now = int(time.time())
        reset_at = ((now // window_seconds) + 1) * window_seconds
        bucket = f"{key}:{now // window_seconds}"
        if self._redis is not None:
            pipeline = self._redis.pipeline()
            pipeline.incr(bucket)
            pipeline.expire(bucket, window_seconds + 2)
            count, _ = pipeline.execute()
        else:
            with self._lock:
                self._local = {k: v for k, v in self._local.items() if v[1] > now}
                count, _ = self._local.get(bucket, (0, reset_at))
                count += 1
                self._local[bucket] = (count, reset_at)
        return count <= limit, max(limit - count, 0), reset_at


rate_limit_backend = RateLimitBackend()
