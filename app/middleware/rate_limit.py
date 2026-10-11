import os
import time
from collections import defaultdict, deque
from threading import Lock

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse


def _rate_limit_disabled() -> bool:
    if os.environ.get("SENTINEL_RATE_LIMIT_DISABLED") == "1":
        return True
    return "PYTEST_CURRENT_TEST" in os.environ


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Reject flooding clients with a per-IP sliding window."""

    def __init__(
        self,
        app,
        max_requests: int = 120,
        window_seconds: int = 60,
        login_max_requests: int = 12,
    ):
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.login_max_requests = login_max_requests
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()
        self.rejected = 0

    def _allow(self, key: str, limit: int) -> bool:
        now = time.monotonic()
        with self._lock:
            bucket = self._hits[key]
            cutoff = now - self.window_seconds
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= limit:
                self.rejected += 1
                return False
            bucket.append(now)
            return True

    async def dispatch(self, request: Request, call_next):
        if _rate_limit_disabled():
            return await call_next(request)

        client = request.client.host if request.client else "unknown"
        path = request.url.path
        limit = self.max_requests
        if path.endswith("/auth/login") or path.endswith("/auth/register"):
            limit = self.login_max_requests
            key = f"{client}:auth"
        else:
            key = client

        if not self._allow(key, limit):
            from app.monitor.sentinel import record_local_event

            record_local_event(
                "flood",
                f"Rate limit exceeded for {key}.",
            )
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Too many requests. Slow down to protect availability."
                },
            )

        return await call_next(request)


rate_limit_middleware = RateLimitMiddleware
