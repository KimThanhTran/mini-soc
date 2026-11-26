import json
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))

import web_honeypot  # noqa: E402
from ship import Shipper, signed_headers  # noqa: E402


def drain(shipper):
    out = []
    while not shipper.queue.empty():
        out.append(shipper.queue.get_nowait())
    return out


@pytest.fixture
def client():
    drain(web_honeypot.shipper)
    return TestClient(web_honeypot.app)  # no `with`: the lifespan (and the network shipper) is not started


def test_bait_pages_and_everything_else(client):
    assert client.get("/admin").status_code == 200
    assert client.get("/.env").status_code == 404
    events = drain(web_honeypot.shipper)
    assert [(e["data"]["path"], e["data"]["status"]) for e in events] == [("/admin", 200), ("/.env", 404)]
    assert events[0]["source"] == "honeypot_web"


def test_credentials_are_captured_refused_and_never_echoed(client):
    r = client.post("/login", data={"username": "<script>alert(1)</script>", "password": "hunter2"})
    assert r.status_code == 401 and "script" not in r.text and "hunter2" not in r.text
    data = drain(web_honeypot.shipper)[0]["data"]
    assert data["username"] == "<script>alert(1)</script>" and data["password"] == "hunter2" and data["status"] == 401


def test_query_string_is_kept_and_oversized_values_are_cut(client):
    client.post("/login", data={"username": "u" * 500, "password": "p" * 500}, headers={"User-Agent": "x" * 1000})
    client.get("/search?q=1' OR '1'='1")
    first, second = drain(web_honeypot.shipper)
    assert len(first["data"]["username"]) == 128 and len(first["data"]["password"]) == 64 and len(first["data"]["user_agent"]) == 300
    assert second["data"]["path"].endswith("q=1' OR '1'='1") or "OR" in second["data"]["path"]


def test_forwarded_for_is_ignored_unless_the_lab_switch_is_on(client, monkeypatch):
    client.get("/admin", headers={"X-Forwarded-For": "10.4.4.4"})
    assert drain(web_honeypot.shipper)[0]["data"]["src_ip"] != "10.4.4.4"
    monkeypatch.setattr(web_honeypot, "TRUST_XFF", True)
    client.get("/admin", headers={"X-Forwarded-For": "10.4.4.4"})
    assert drain(web_honeypot.shipper)[0]["data"]["src_ip"] == "10.4.4.4"


def test_signature_matches_what_the_api_verifies():
    from app.security import ReplayCache, verify
    body = json.dumps({"events": []}).encode()
    h = signed_headers("web-honeypot", "k" * 20, body)
    assert verify({"web-honeypot": "k" * 20}, ReplayCache(), h["X-Sensor-Id"], h["X-Timestamp"], h["X-Signature"], body,
                  now=time.time()) == "web-honeypot"


def test_a_full_queue_drops_records_instead_of_blocking():
    s = Shipper("honeypot_ssh", "h", api_url="http://x", sensor_id="x", secret="y", max_queue=2)
    for _ in range(5):
        s.emit({"src_ip": "10.3.1.1"})
    assert s.queue.qsize() == 2


def test_a_batch_the_api_keeps_failing_on_is_dropped_so_the_sensor_keeps_working(monkeypatch):
    import asyncio

    import httpx

    import ship

    calls = []

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, content, headers):
            calls.append(json.loads(content)["events"][0]["data"]["n"])
            return httpx.Response(500) if len(calls) <= ship.MAX_SERVER_ERRORS else httpx.Response(202)

    monkeypatch.setattr(ship.httpx, "AsyncClient", FakeClient)
    monkeypatch.setattr(ship, "BACKOFF_START", 0.001)

    async def until(condition):
        for _ in range(500):
            if condition():
                return
            await asyncio.sleep(0.01)
        raise AssertionError(calls)

    async def scenario():
        s = ship.Shipper("honeypot_ssh", "h", api_url="http://x", sensor_id="x", secret="y")
        task = asyncio.create_task(s.run())
        s.emit({"n": 1})
        await until(lambda: len(calls) == ship.MAX_SERVER_ERRORS)
        s.emit({"n": 2})  # the sensor still works after dropping batch 1
        await until(lambda: 2 in calls)
        task.cancel()

    asyncio.run(scenario())
    assert calls.count(1) == ship.MAX_SERVER_ERRORS
