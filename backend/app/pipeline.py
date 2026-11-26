"""Glue: normalise a batch, store it, run the rules, turn matches into alerts and incidents; plus the anomaly scorer's tick."""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import incidents
from .config import Settings
from .db import AlertRow, EventRow, utc
from .engine import Engine, Match
from .ml import FEATURES, WINDOW_S, Scorer, features
from .normalize import RawEvent, Rejected, normalize
from .security import RateLimiter, ReplayCache

ML_RULE = "ml-isolation-forest"
ML_QUIET = timedelta(minutes=15)


@dataclass
class State:
    settings: Settings
    sessions: object  # sessionmaker
    engine: Engine
    scorer: Scorer | None = None
    cursor: int = 0  # the anomaly scorer has seen every event up to this id
    lock: threading.Lock = field(default_factory=threading.Lock)  # the engine's windows are one shared in-memory state
    replay: ReplayCache = field(default_factory=ReplayCache)
    ml_quiet: dict = field(default_factory=dict)
    ingest_limiter: RateLimiter = None
    api_limiter: RateLimiter = None

    def __post_init__(self):
        self.ingest_limiter = RateLimiter(self.settings.ingest_rpm)
        self.api_limiter = RateLimiter(self.settings.api_rpm)


def record_alert(db: Session, *, rule_id, title, severity, techniques, incident_type, ts, src_ip, user, summary, event_ids):
    alert = AlertRow(ts=ts, rule_id=rule_id, title=title, severity=severity, techniques=techniques,
                     incident_type=incident_type, src_ip=src_ip, user=user, summary=summary, event_ids=event_ids)
    db.add(alert)
    db.flush()
    incidents.attach(db, alert)
    return alert


def _from_match(db: Session, m: Match) -> AlertRow:
    r = m.rule
    return record_alert(db, rule_id=r.id, title=r.title, severity=r.level, techniques=r.techniques,
                        incident_type=r.incident_type, ts=m.ts, src_ip=m.src_ip, user=m.user, summary=m.summary,
                        event_ids=m.event_ids)


def ingest(state: State, db: Session, raws: list[RawEvent], sensor: str) -> dict:
    rejected, rows = [], []
    with state.lock:
        for i, raw in enumerate(raws):
            try:
                ev = normalize(raw.model_dump())
            except Rejected as why:
                rejected.append({"index": i, "reason": str(why)})
                continue
            row = EventRow(**ev, sensor=sensor)
            db.add(row)
            rows.append((row, ev))
        db.flush()
        alerts = 0
        for row, ev in rows:
            ev["id"] = row.id
            for match in state.engine.process(ev):
                _from_match(db, match)
                alerts += 1
        db.commit()
    return {"accepted": len(rows), "rejected": rejected, "alerts": alerts}


def _as_dict(row: EventRow) -> dict:
    return {c: getattr(row, c) for c in ("id", "source", "src_ip", "user", "action", "outcome", "http_status")} | {"ts": utc(row.ts)}


def ml_tick(state: State, db: Session) -> int:
    """Scores every source that sent events since the last tick, over its own trailing five minutes. Returns alerts raised."""
    if state.scorer is None:
        return 0
    with state.lock:
        seen = db.execute(select(EventRow.src_ip, func.max(EventRow.ts), func.max(EventRow.id))
                          .where(EventRow.id > state.cursor, EventRow.src_ip.is_not(None))
                          .group_by(EventRow.src_ip)).all()
        if not seen:
            return 0
        state.cursor = max(row[2] for row in seen)
        raised = 0
        for ip, last, _ in seen:
            end = utc(last) if isinstance(last, datetime) else utc(datetime.fromisoformat(str(last)))
            rows = db.scalars(select(EventRow).where(EventRow.src_ip == ip, EventRow.ts >= end - timedelta(seconds=WINDOW_S),
                                                     EventRow.ts <= end).order_by(EventRow.ts)).all()
            vec = features([_as_dict(r) for r in rows])
            if vec is None:
                continue
            score = state.scorer.score([vec])[0]
            if score >= 0 or end < state.ml_quiet.get(ip, end - timedelta(seconds=1)):
                continue
            state.ml_quiet[ip] = end + ML_QUIET
            detail = ", ".join(f"{n.replace('_', ' ')} {v:.2f}" for n, v in zip(FEATURES, vec))
            record_alert(db, rule_id=ML_RULE, title="Anomalous behaviour (IsolationForest)", severity="medium",
                         techniques=[], incident_type="anomaly", ts=end, src_ip=ip, user=None, event_ids=[r.id for r in rows][-20:],
                         summary=f"{ip}: {detail} over the last 5 min (anomaly score {score:.3f})")
            raised += 1
        db.commit()
    return raised
