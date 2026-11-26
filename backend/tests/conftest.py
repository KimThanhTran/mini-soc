import itertools
from datetime import datetime, timedelta, timezone

import pytest

from app.engine import Engine
from app.normalize import geo_lookup
from app.rules import load_rules

T0 = datetime(2026, 3, 1, 8, 0, tzinfo=timezone.utc)
_ids = itertools.count(1)


def ev(seconds: float = 0, **kw) -> dict:
    """A normalised event `seconds` after T0; defaults to a failed SSH login."""
    e = dict(id=next(_ids), ts=T0 + timedelta(seconds=seconds), source="ssh", host="h", src_ip="10.3.1.1", user="root",
             action="auth", outcome="failure", http_method=None, http_path=None, http_status=None, user_agent=None,
             extra={})
    e.update(kw)
    e.setdefault("geo_country", geo_lookup(e["src_ip"])[0])
    e.setdefault("geo_lat", geo_lookup(e["src_ip"])[1])
    e.setdefault("geo_lon", geo_lookup(e["src_ip"])[2])
    return e


def http(seconds, path, status=200, ip="10.3.1.1"):
    return ev(seconds, action="http_request", source="web", outcome=None, user=None, http_method="GET", http_path=path,
              http_status=status, src_ip=ip)


def fired(engine: Engine, events: list[dict]) -> list[str]:
    return [m.rule.id for e in events for m in engine.process(e)]


@pytest.fixture(scope="session")
def rules():
    return load_rules()


@pytest.fixture
def engine(rules):
    return Engine(rules)
