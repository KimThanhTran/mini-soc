"""Anomaly detection: an IsolationForest over four behaviour features of one source address in a five-minute window."""
from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta

from sklearn.ensemble import IsolationForest

WINDOW_S = 300
STEP_S = 60  # offline replay re-scores every source once a minute of event time
MIN_EVENTS = 5  # a window with fewer events is not scored: too little to judge
FEATURES = ("failed_logins_per_min", "distinct_usernames", "requests_per_min", "error_ratio")


def features(events: list[dict]) -> list[float] | None:
    """Feature vector for one source's events in the window, or None when there is too little activity."""
    if len(events) < MIN_EVENTS:
        return None
    minutes = WINDOW_S / 60
    auth = [e for e in events if e["action"] == "auth"]
    web = [e for e in events if e["action"] == "http_request"]
    failed = sum(e["outcome"] == "failure" for e in auth)
    errors = sum((e.get("http_status") or 0) >= 400 for e in web)
    return [failed / minutes, float(len({e["user"] for e in auth if e.get("user")})), len(web) / minutes,
            errors / len(web) if web else 0.0]


def replay(events: list[dict]):
    """Yields (time, src_ip, vector) the way the live scorer sees traffic: trailing windows per source, once per step."""
    windows: dict[str, deque] = defaultdict(deque)
    dirty: set[str] = set()
    boundary = None

    def flush(at):
        for ip in sorted(dirty):
            window = windows[ip]
            while window and (at - window[0]["ts"]).total_seconds() > WINDOW_S:
                window.popleft()
            if (vec := features(list(window))) is not None:
                yield at, ip, vec
        dirty.clear()

    for ev in sorted((e for e in events if e.get("src_ip")), key=lambda e: e["ts"]):
        if boundary is None:
            boundary = ev["ts"] + timedelta(seconds=STEP_S)
        if ev["ts"] >= boundary:
            yield from flush(boundary)
            boundary = ev["ts"] + timedelta(seconds=STEP_S)
        windows[ev["src_ip"]].append(ev)
        dirty.add(ev["src_ip"])
    if boundary is not None:
        yield from flush(boundary)


class Scorer:
    """decision_function < 0 means anomalous. contamination is the share of the baseline allowed to look anomalous."""

    def __init__(self, contamination: float = 0.02, seed: int = 0):
        self.model = IsolationForest(n_estimators=200, contamination=contamination, random_state=seed)

    def fit(self, vectors: list[list[float]]) -> "Scorer":
        self.model.fit(vectors)
        return self

    def score(self, vectors: list[list[float]]) -> list[float]:
        return list(self.model.decision_function(vectors))


def to_event(raw: dict) -> dict:
    from .normalize import RawEvent, normalize
    return normalize(RawEvent(**raw).model_dump(), check_time=False)


def train_default(seed: int = 1, hours: int = 6, contamination: float = 0.02) -> Scorer:
    """Trains on generated benign traffic only (no attacks), as a real deployment would on a clean baseline period."""
    import random
    from datetime import datetime, timezone

    from .simulation import benign
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = [to_event(i.raw) for i in benign(random.Random(seed), start, hours * 60)]
    return Scorer(contamination).fit([vec for _, _, vec in replay(events)])
