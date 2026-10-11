from app.middleware.rate_limit import RateLimitMiddleware
from app.services.message_inbox import MessageInbox


def test_rate_limiter_rejects_flood():
    limiter = RateLimitMiddleware.__new__(RateLimitMiddleware)
    limiter.max_requests = 3
    limiter.window_seconds = 60
    limiter.login_max_requests = 3
    limiter._hits = __import__("collections").defaultdict(__import__("collections").deque)
    limiter._lock = __import__("threading").Lock()
    limiter.rejected = 0

    assert limiter._allow("client", 3) is True
    assert limiter._allow("client", 3) is True
    assert limiter._allow("client", 3) is True
    assert limiter._allow("client", 3) is False
    assert limiter.rejected == 1


def test_inbox_rejects_flood():
    inbox = MessageInbox(max_messages=2)
    inbox.enqueue("s", {"sequence_number": 0})
    inbox.enqueue("s", {"sequence_number": 1})
    try:
        inbox.enqueue("s", {"sequence_number": 2})
        assert False, "expected overflow"
    except OverflowError:
        pass
