"""Request authentication for sensors (HMAC over timestamp + body, with replay protection) and a token-bucket rate limiter."""
from __future__ import annotations

import hashlib
import hmac
import time
from collections import OrderedDict

SKEW_S = 300


class AuthError(Exception):
    pass


def sign(secret: str, timestamp: int, body: bytes) -> str:
    return hmac.new(secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256).hexdigest()


class ReplayCache:
    """Remembers signatures for the length of the accepted clock skew, so a captured request cannot be sent again."""

    def __init__(self):
        self._seen: OrderedDict[str, float] = OrderedDict()

    def check_and_add(self, signature: str, now: float) -> bool:
        while self._seen and next(iter(self._seen.values())) < now:
            self._seen.popitem(last=False)
        if signature in self._seen:
            return False
        self._seen[signature] = now + 2 * SKEW_S
        return True


def verify(keys: dict[str, str], replay: ReplayCache, sensor: str | None, timestamp: str | None,
           signature: str | None, body: bytes, now: float | None = None) -> str:
    """Returns the sensor id or raises AuthError. One generic message, so callers learn nothing about which part failed."""
    now = time.time() if now is None else now
    secret = keys.get(sensor or "")
    try:
        ts = int(timestamp or "")
    except ValueError:
        raise AuthError("invalid signature") from None
    expected = sign(secret or "x" * 16, ts, body)
    if secret is None or abs(now - ts) > SKEW_S or not hmac.compare_digest(expected, signature or ""):
        raise AuthError("invalid signature")
    if not replay.check_and_add(signature, now):
        raise AuthError("invalid signature")
    return sensor


class RateLimiter:
    def __init__(self, per_minute: int):
        self.rate, self.capacity = per_minute / 60, float(per_minute)
        self.buckets: dict[str, tuple[float, float]] = {}

    def allow(self, key: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        if len(self.buckets) > 10_000:  # shortcut: forget everyone rather than track an unbounded set of clients
            self.buckets.clear()
        tokens, last = self.buckets.get(key, (self.capacity, now))
        tokens = min(self.capacity, tokens + (now - last) * self.rate)
        if tokens < 1:
            self.buckets[key] = (tokens, now)
            return False
        self.buckets[key] = (tokens - 1, now)
        return True
