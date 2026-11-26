import json
import time
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.pipeline import ml_tick
from app.security import sign

SECRET, TOKEN = "s" * 24, "t" * 24
AUTH = {"Authorization": f"Bearer {TOKEN}"}


def settings(**kw):
    return Settings(database_url="sqlite:///:memory:", sensor_keys={"sim": SECRET}, analyst_token=TOKEN, ml_enabled=False, **kw)


@pytest.fixture
def client():
    with TestClient(create_app(settings())) as c:
        yield c


def post(client, events, sensor="sim", secret=SECRET, ts=None, raw=None):
    body = raw if raw is not None else json.dumps({"events": events}).encode()
    ts = int(time.time()) if ts is None else ts
    headers = {"X-Sensor-Id": sensor, "X-Timestamp": str(ts), "X-Signature": sign(secret, ts, body),
               "Content-Type": "application/json"}
    return client.post("/api/ingest", content=body, headers=headers)


def ssh_failures(n, ip="10.5.1.1"):
    now = datetime.now(timezone.utc)
    return [{"source": "ssh", "ts": (now - timedelta(seconds=n - i)).isoformat(),
             "message": f"sshd[1]: Failed password for root from {ip} port 22 ssh2"} for i in range(n)]


def test_unsigned_and_mis_signed_requests_are_refused(client):
    body = json.dumps({"events": ssh_failures(1)}).encode()
    assert client.post("/api/ingest", content=body).status_code == 401
    assert post(client, ssh_failures(1), sensor="nobody").status_code == 401
    assert post(client, ssh_failures(1), secret="x" * 24).status_code == 401
    assert post(client, ssh_failures(1), ts=int(time.time()) - 1000).status_code == 401  # stale timestamp
    assert post(client, ssh_failures(1)).status_code == 202


def test_a_captured_request_cannot_be_replayed(client):
    body = json.dumps({"events": ssh_failures(1)}).encode()
    ts = int(time.time())
    headers = {"X-Sensor-Id": "sim", "X-Timestamp": str(ts), "X-Signature": sign(SECRET, ts, body)}
    assert client.post("/api/ingest", content=body, headers=headers).status_code == 202
    assert client.post("/api/ingest", content=body, headers=headers).status_code == 401


def test_tampered_body_fails_the_signature(client):
    body = json.dumps({"events": ssh_failures(1)}).encode()
    ts = int(time.time())
    headers = {"X-Sensor-Id": "sim", "X-Timestamp": str(ts), "X-Signature": sign(SECRET, ts, body)}
    assert client.post("/api/ingest", content=body.replace(b"root", b"r00t"), headers=headers).status_code == 401


def test_the_analyst_api_needs_the_token(client):
    for path in ("/api/alerts", "/api/incidents", "/api/stats", "/api/coverage"):
        assert client.get(path).status_code == 401
        assert client.get(path, headers={"Authorization": "Bearer wrong"}).status_code == 401
        assert client.get(path, headers=AUTH).status_code == 200
    assert client.get("/healthz").status_code == 200


def test_brute_force_becomes_an_alert_and_one_incident(client):
    r = post(client, ssh_failures(12))
    assert r.status_code == 202 and r.json()["accepted"] == 12 and r.json()["alerts"] == 1
    alerts = client.get("/api/alerts", headers=AUTH).json()
    assert alerts[0]["rule_id"] == "ssh-brute-force" and alerts[0]["techniques"] == ["T1110.001"]
    incidents = client.get("/api/incidents", headers=AUTH).json()
    assert len(incidents) == 1 and incidents[0]["entity"] == "10.5.1.1" and incidents[0]["alert_count"] == 1
    detail = client.get(f"/api/incidents/{incidents[0]['id']}", headers=AUTH).json()
    assert detail["status"] == "new" and detail["playbook"] and detail["timeline"][0]["kind"] == "alert"
    stats = client.get("/api/stats", headers=AUTH).json()
    assert stats["events"] == 12 and stats["top_attackers"][0]["ip"] == "10.5.1.1"
    coverage = client.get("/api/coverage", headers=AUTH).json()
    cred = next(t for t in coverage["tactics"] if t["id"] == "credential_access")
    assert next(t for t in cred["techniques"] if t["id"] == "T1110.001")["alerts"] == 1


def test_incident_work_flow(client):
    post(client, ssh_failures(12))
    i = client.get("/api/incidents", headers=AUTH).json()[0]["id"]
    url = f"/api/incidents/{i}"
    assert client.patch(url, json={"status": "contained"}, headers=AUTH).status_code == 409  # must investigate first
    r = client.patch(url, json={"status": "investigating", "notes": "looks like a botnet"}, headers=AUTH)
    assert r.status_code == 200 and r.json()["status"] == "investigating" and r.json()["notes"] == "looks like a botnet"
    assert client.post(f"{url}/playbook/0", json={"done": True}, headers=AUTH).json()["playbook"][0]["done"] is True
    assert client.post(f"{url}/playbook/99", json={"done": True}, headers=AUTH).status_code == 404
    assert client.patch(url, json={"status": "bogus"}, headers=AUTH).status_code == 422
    assert client.patch(url, json={"notes": "x" * 10_001}, headers=AUTH).status_code == 422
    assert client.patch("/api/incidents/999", json={"notes": "x"}, headers=AUTH).status_code == 404
    kinds = [e["kind"] for e in client.get(url, headers=AUTH).json()["timeline"]]
    assert {"alert", "status", "note", "playbook"} <= set(kinds)


def test_bad_input_is_rejected_or_reported(client):
    assert post(client, [], ).status_code == 422
    assert post(client, [{"source": "carrier-pigeon", "message": "x"}]).status_code == 422
    assert post(client, [{"source": "ssh", "message": "x" * 3000}]).status_code == 422
    assert post(client, ssh_failures(1) * 501).status_code == 422  # over the batch limit
    assert post(client, [], raw=b"not json").status_code == 422
    r = post(client, [{"source": "ssh", "message": "nonsense"}, *ssh_failures(1)]).json()
    assert r["accepted"] == 1 and r["rejected"] == [{"index": 0, "reason": "unrecognised sshd line"}]


def test_oversized_body_is_refused(client):
    big = b"{" + b" " * 1_100_000 + b"}"
    assert post(client, [], raw=big).status_code == 413


def test_rate_limits():
    with TestClient(create_app(settings(ingest_rpm=3, api_rpm=3))) as c:
        codes = [post(c, ssh_failures(1)).status_code for _ in range(5)]
        assert codes.count(429) == 2 and codes[0] == 202
        codes = [c.get("/api/alerts", headers=AUTH).status_code for _ in range(5)]
        assert codes == [200, 200, 200, 429, 429]


def test_settings_refuse_weak_secrets():
    with pytest.raises(ValueError):
        Settings(database_url="x", sensor_keys={"a": "short"}, analyst_token=TOKEN)
    with pytest.raises(ValueError):
        Settings(database_url="x", sensor_keys={"a": SECRET}, analyst_token="short")
    with pytest.raises(ValueError):
        Settings(database_url="x", sensor_keys={}, analyst_token=TOKEN)


def test_anomaly_scorer_raises_an_alert_the_rules_miss():
    from app.ml import train_default
    with TestClient(create_app(settings())) as c:
        state = c.app.state.s
        state.scorer = train_default(hours=2)
        now = datetime.now(timezone.utc)
        events = [{"source": "web", "ts": (now - timedelta(seconds=290 - i * 6)).isoformat(),
                   "message": f'10.7.3.3 - - [01/Mar/2026:08:00:00 +0000] "GET /x{i} HTTP/1.1" 404 9 "-" "probe"'}
                  for i in range(48)]  # ten 404s a minute: under the 15-a-minute rule
        r = post(c, events)
        assert r.json()["alerts"] == 0
        with state.sessions() as db:
            assert ml_tick(state, db) == 1
            assert ml_tick(state, db) == 0  # nothing new
        alert = c.get("/api/alerts", headers=AUTH).json()[0]
        assert alert["rule_id"] == "ml-isolation-forest" and alert["src_ip"] == "10.7.3.3" and alert["techniques"] == []
