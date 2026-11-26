"""Database tables. Schema is created on start (create_all); a real deployment would add Alembic migrations."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, ForeignKey, Index, Integer, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool


class Base(DeclarativeBase):
    pass


class EventRow(Base):
    __tablename__ = "events"
    __table_args__ = (Index("ix_events_ip_ts", "src_ip", "ts"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    source: Mapped[str] = mapped_column(String(32))
    host: Mapped[str] = mapped_column(String(255))
    src_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user: Mapped[str | None] = mapped_column(String(128), nullable=True)
    action: Mapped[str] = mapped_column(String(32))
    outcome: Mapped[str | None] = mapped_column(String(16), nullable=True)
    http_method: Mapped[str | None] = mapped_column(String(16), nullable=True)
    http_path: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(300), nullable=True)
    geo_country: Mapped[str | None] = mapped_column(String(2), nullable=True)
    geo_lat: Mapped[float | None] = mapped_column(nullable=True)
    geo_lon: Mapped[float | None] = mapped_column(nullable=True)
    extra: Mapped[dict] = mapped_column(JSON, default=dict)
    sensor: Mapped[str] = mapped_column(String(64), default="")


class IncidentRow(Base):
    __tablename__ = "incidents"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    entity: Mapped[str] = mapped_column(String(128), index=True)
    entity_kind: Mapped[str] = mapped_column(String(8))  # ip | user
    types: Mapped[list] = mapped_column(JSON, default=list)
    severity: Mapped[str] = mapped_column(String(10))
    status: Mapped[str] = mapped_column(String(16), default="new", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    notes: Mapped[str] = mapped_column(Text, default="")
    playbook: Mapped[list] = mapped_column(JSON, default=list)  # [{type, step, done}]
    timeline: Mapped[list] = mapped_column(JSON, default=list)  # [{ts, kind, text}]


class AlertRow(Base):
    __tablename__ = "alerts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(200))
    severity: Mapped[str] = mapped_column(String(10))
    techniques: Mapped[list] = mapped_column(JSON, default=list)
    incident_type: Mapped[str] = mapped_column(String(32))
    src_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    user: Mapped[str | None] = mapped_column(String(128), nullable=True)
    summary: Mapped[str] = mapped_column(Text)
    event_ids: Mapped[list] = mapped_column(JSON, default=list)
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id"), nullable=True, index=True)


def utc(dt: datetime) -> datetime:
    """SQLite hands datetimes back naive; everything stored here is UTC."""
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def make_session_factory(url: str):
    kwargs = {}
    if url.startswith("sqlite") and ":memory:" in url:
        kwargs = {"connect_args": {"check_same_thread": False}, "poolclass": StaticPool}
    engine = create_engine(url, pool_pre_ping=True, **kwargs)
    Base.metadata.create_all(engine)
    return sessionmaker(engine, expire_on_commit=False)
