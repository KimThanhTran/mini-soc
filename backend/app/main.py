"""HTTP API. Sensors post signed batches to /api/ingest; analysts read and work incidents with a bearer token."""
from __future__ import annotations

import asyncio
import hmac
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import func, select

from . import incidents
from .attack import TACTICS, TECHNIQUES
from .config import Settings
from .db import AlertRow, EventRow, IncidentRow, make_session_factory, utc
from .engine import Engine
from .ml import train_default
from .normalize import RawEvent
from .pipeline import ML_RULE, State, ingest, ml_tick
from .rules import load_rules
from .security import AuthError, verify

log = logging.getLogger("minisoc")


class IngestBatch(BaseModel):
    events: list[RawEvent]


class IncidentPatch(BaseModel):
    status: Literal["new", "investigating", "contained", "closed"] | None = None
    notes: str | None = Field(default=None, max_length=10_000)


class StepPatch(BaseModel):
    done: bool


def _iso(dt: datetime) -> str:
    return utc(dt).isoformat()


def alert_json(a: AlertRow) -> dict:
    return {"id": a.id, "ts": _iso(a.ts), "rule_id": a.rule_id, "title": a.title, "severity": a.severity,
            "techniques": a.techniques, "incident_type": a.incident_type, "src_ip": a.src_ip, "user": a.user,
            "summary": a.summary, "incident_id": a.incident_id}


def incident_json(i: IncidentRow, alert_count: int | None = None, detail: bool = False) -> dict:
    out = {"id": i.id, "entity": i.entity, "entity_kind": i.entity_kind, "types": i.types, "severity": i.severity,
           "status": i.status, "created_at": _iso(i.created_at), "updated_at": _iso(i.updated_at), "alert_count": alert_count}
    if detail:
        out |= {"notes": i.notes, "playbook": i.playbook, "timeline": i.timeline}
    return out


async def _ml_loop(state: State):
    while True:
        await asyncio.sleep(state.settings.ml_interval)
        try:
            def tick():
                with state.sessions() as db:
                    return ml_tick(state, db)
            await run_in_threadpool(tick)
        except Exception:  # keep scoring alive across a bad tick
            log.exception("anomaly scoring tick failed")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    if any("demo" in v for v in [settings.analyst_token, *settings.sensor_keys.values()]):
        log.warning("running with DEMO secrets: fine on a laptop, never on a network others can reach")

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        sessions = make_session_factory(settings.database_url)
        state = State(settings, sessions, Engine(load_rules()))
        with sessions() as db:
            state.cursor = db.scalar(select(func.coalesce(func.max(EventRow.id), 0)))
        task = None
        if settings.ml_enabled:
            state.scorer = await run_in_threadpool(train_default)
            task = asyncio.create_task(_ml_loop(state))
        app.state.s = state
        yield
        if task:
            task.cancel()

    app = FastAPI(title="mini-soc", version="1.0.0", lifespan=lifespan, docs_url="/api/docs", openapi_url="/api/openapi.json")

    def get_state(request: Request) -> State:
        return request.app.state.s

    def get_db(state: State = Depends(get_state)):
        with state.sessions() as db:
            yield db

    def analyst(request: Request, state: State = Depends(get_state)):
        if not state.api_limiter.allow(request.client.host if request.client else "?"):
            raise HTTPException(429, "too many requests")
        token = request.headers.get("authorization", "").removeprefix("Bearer ")
        if not hmac.compare_digest(token.encode(), state.settings.analyst_token.encode()):
            raise HTTPException(401, "invalid token")

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    @app.post("/api/ingest", status_code=202)
    async def ingest_endpoint(request: Request, state: State = Depends(get_state)):
        s = state.settings
        if not state.ingest_limiter.allow(request.client.host if request.client else "?"):
            raise HTTPException(429, "too many requests")
        if int(request.headers.get("content-length") or 0) > s.max_body:
            raise HTTPException(413, "body too large")
        body = await request.body()
        if len(body) > s.max_body:
            raise HTTPException(413, "body too large")
        try:
            sensor = verify(s.sensor_keys, state.replay, request.headers.get("x-sensor-id"),
                            request.headers.get("x-timestamp"), request.headers.get("x-signature"), body)
        except AuthError as e:
            raise HTTPException(401, str(e)) from None
        try:
            batch = IngestBatch.model_validate_json(body)
        except ValidationError as e:
            raise HTTPException(422, e.errors(include_input=False, include_url=False)[:5]) from None
        if not 0 < len(batch.events) <= s.max_batch:
            raise HTTPException(422, f"send between 1 and {s.max_batch} events per request")

        def work():
            with state.sessions() as db:
                return ingest(state, db, batch.events, sensor)
        return await run_in_threadpool(work)

    @app.get("/api/alerts", dependencies=[Depends(analyst)])
    def alerts(limit: int = 50, db=Depends(get_db)):
        rows = db.scalars(select(AlertRow).order_by(AlertRow.id.desc()).limit(min(max(limit, 1), 200))).all()
        return [alert_json(a) for a in rows]

    @app.get("/api/incidents", dependencies=[Depends(analyst)])
    def list_incidents(status: str | None = None, db=Depends(get_db)):
        q = select(IncidentRow, func.count(AlertRow.id)).join(AlertRow, AlertRow.incident_id == IncidentRow.id, isouter=True)
        if status:
            q = q.where(IncidentRow.status == status)
        rows = db.execute(q.group_by(IncidentRow.id).order_by(IncidentRow.updated_at.desc()).limit(200)).all()
        return [incident_json(i, n) for i, n in rows]

    def _incident(db, incident_id: int) -> IncidentRow:
        incident = db.get(IncidentRow, incident_id)
        if incident is None:
            raise HTTPException(404, "no such incident")
        return incident

    @app.get("/api/incidents/{incident_id}", dependencies=[Depends(analyst)])
    def incident_detail(incident_id: int, db=Depends(get_db)):
        incident = _incident(db, incident_id)
        alerts = db.scalars(select(AlertRow).where(AlertRow.incident_id == incident_id).order_by(AlertRow.id)).all()
        return incident_json(incident, len(alerts), detail=True) | {"alerts": [alert_json(a) for a in alerts]}

    @app.patch("/api/incidents/{incident_id}", dependencies=[Depends(analyst)])
    def patch_incident(incident_id: int, patch: IncidentPatch, state: State = Depends(get_state), db=Depends(get_db)):
        with state.lock:
            incident = _incident(db, incident_id)
            try:
                if patch.status:
                    incidents.change_status(incident, patch.status)
            except ValueError as e:
                raise HTTPException(409, str(e)) from None
            if patch.notes is not None:
                incidents.add_note(incident, patch.notes)
            db.commit()
        return incident_json(incident, detail=True)

    @app.post("/api/incidents/{incident_id}/playbook/{index}", dependencies=[Depends(analyst)])
    def playbook_step(incident_id: int, index: int, patch: StepPatch, state: State = Depends(get_state), db=Depends(get_db)):
        with state.lock:
            incident = _incident(db, incident_id)
            try:
                incidents.set_step(incident, index, patch.done)
            except IndexError:
                raise HTTPException(404, "no such playbook step") from None
            db.commit()
        return incident_json(incident, detail=True)

    @app.get("/api/stats", dependencies=[Depends(analyst)])
    def stats(db=Depends(get_db)):
        latest = db.scalar(select(func.max(AlertRow.ts)))
        end = utc(latest) if latest else datetime.now(timezone.utc)
        recent = db.scalars(select(AlertRow.ts).where(AlertRow.ts >= end - timedelta(minutes=60))).all()
        buckets = [0] * 12  # twelve five-minute buckets ending at the newest alert
        for ts in recent:
            buckets[11 - min(11, int((end - utc(ts)).total_seconds() // 300))] += 1
        severities = dict(db.execute(select(AlertRow.severity, func.count()).group_by(AlertRow.severity)).all())
        by_status = dict(db.execute(select(IncidentRow.status, func.count()).group_by(IncidentRow.status)).all())
        top = db.execute(select(AlertRow.src_ip, func.count()).where(AlertRow.src_ip.is_not(None))
                         .group_by(AlertRow.src_ip).order_by(func.count().desc()).limit(8)).all()
        countries = dict(db.execute(select(EventRow.src_ip, EventRow.geo_country).where(
            EventRow.src_ip.in_([t[0] for t in top])).group_by(EventRow.src_ip, EventRow.geo_country)).all())
        return {"events": db.scalar(select(func.count(EventRow.id))), "alerts": sum(severities.values()),
                "severities": severities, "incidents": by_status, "alerts_per_5min": buckets,
                "top_attackers": [{"ip": ip, "alerts": n, "country": countries.get(ip)} for ip, n in top]}

    @app.get("/api/coverage", dependencies=[Depends(analyst)])
    def coverage(state: State = Depends(get_state), db=Depends(get_db)):
        per_rule = dict(db.execute(select(AlertRow.rule_id, func.count()).group_by(AlertRow.rule_id)).all())
        tactics = []
        for tid, name in TACTICS:
            techs: dict[str, dict] = {}
            for r in state.engine.rules:
                if tid in r.tactics:
                    for t in r.techniques:
                        entry = techs.setdefault(t, {"id": t, "name": TECHNIQUES[t], "rules": [], "alerts": 0})
                        entry["rules"].append(r.id)
                        entry["alerts"] += per_rule.get(r.id, 0)
            tactics.append({"id": tid, "name": name, "techniques": list(techs.values())})
        return {"tactics": tactics, "rules": len(state.engine.rules), "ml_alerts": per_rule.get(ML_RULE, 0)}

    return app
