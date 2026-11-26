from datetime import datetime, timedelta, timezone

import pytest

from app.normalize import RawEvent, Rejected, normalize


def norm(source, message=None, data=None, ts=None, host="h"):
    return normalize(RawEvent(source=source, message=message, data=data, ts=ts, host=host).model_dump())


def test_ssh_failed_password():
    e = norm("ssh", "sshd[1]: Failed password for invalid user admin from 10.5.1.2 port 4022 ssh2")
    assert (e["action"], e["outcome"], e["user"], e["src_ip"]) == ("auth", "failure", "admin", "10.5.1.2")
    assert e["geo_country"] == "RU"


def test_ssh_accepted_and_sudo():
    ok = norm("ssh", "sshd[1]: Accepted publickey for bob from 10.1.2.3 port 22 ssh2")
    assert (ok["outcome"], ok["user"], ok["geo_country"]) == ("success", "bob", "VN")
    s = norm("ssh", "sudo:   bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash -i")
    assert s["action"] == "sudo" and s["extra"] == {"target_user": "root", "command": "/bin/bash -i"}


def test_web_line_is_decoded_twice_and_keeps_the_raw_path():
    line = '10.4.1.1 - - [01/Mar/2026:08:00:00 +0000] "GET /img?f=..%252f..%252fetc%252fpasswd HTTP/1.1" 404 12 "-" "curl/8"'
    e = norm("web", line, ts=datetime.now(timezone.utc))
    assert e["http_path"] == "/img?f=../../etc/passwd" and "%252f" in e["extra"]["raw_path"]
    assert (e["http_status"], e["http_method"], e["user_agent"]) == (404, "GET", "curl/8")


def test_windows_records():
    assert norm("windows", data={"EventID": 4625, "TargetUserName": "eve", "IpAddress": "10.3.3.3"})["outcome"] == "failure"
    ok = norm("windows", data={"EventID": "4624", "TargetUserName": "eve", "IpAddress": "-", "LogonType": 10})
    assert ok["outcome"] == "success" and ok["src_ip"] is None
    g = norm("windows", data={"EventID": 4732, "SubjectUserName": "eve", "TargetUserName": "Administrators", "MemberName": "eve"})
    assert g["action"] == "group_add" and g["extra"]["group"] == "Administrators"


def test_honeypot_records_keep_the_credentials_truncated():
    ssh = norm("honeypot_ssh", data={"src_ip": "10.3.1.1", "user": "root", "password": "x" * 200})
    assert ssh["outcome"] == "failure" and len(ssh["extra"]["password"]) == 64
    login = norm("honeypot_web", data={"src_ip": "10.3.1.1", "method": "POST", "path": "/login", "status": 401,
                                       "username": "admin", "password": "admin"})
    assert login["action"] == "auth" and login["user"] == "admin"
    page = norm("honeypot_web", data={"src_ip": "10.3.1.1", "method": "GET", "path": "/.env", "status": 404})
    assert page["action"] == "http_request" and page["http_path"] == "/.env"


@pytest.mark.parametrize("source,message,data", [
    ("ssh", "something else entirely", None),
    ("ssh", "Failed password for root from not-an-ip port 22 ssh2", None),
    ("web", "garbage", None),
    ("windows", None, {"EventID": 9999}),
    ("windows", None, {}),
])
def test_unreadable_records_are_rejected(source, message, data):
    with pytest.raises(Rejected):
        norm(source, message, data)


def test_timestamps_outside_the_window_are_rejected():
    line = "Failed password for root from 10.3.1.1 port 22 ssh2"
    now = datetime.now(timezone.utc)
    with pytest.raises(Rejected):
        norm("ssh", line, ts=now - timedelta(days=8))
    with pytest.raises(Rejected):
        norm("ssh", line, ts=now + timedelta(minutes=10))
    assert norm("ssh", line, ts=now - timedelta(days=1))["ts"] < now


def test_unknown_source_is_invalid():
    with pytest.raises(ValueError):
        RawEvent(source="syslog", message="x")


def test_nul_bytes_and_absurd_numbers_cannot_reach_the_database():
    """PostgreSQL rejects NUL in text and 32-bit overflows; SQLite accepts both, so the normaliser has to stop them."""
    web = norm("web", '10.4.1.1 - - [01/Mar/2026:08:00:00 +0000] "GET /a%00b HTTP/1.1" 404 12 "-" "ua\x00"')
    hp = norm("honeypot_web", host="h\x00", data={"src_ip": "10.3.1.1", "path": "/x%00", "status": 10**12, "username": "u\x00", "password": "p\x00"})
    sudo = norm("ssh", "sudo:   bob : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/sh\x00")

    def strings(value):
        if isinstance(value, str):
            yield value
        elif isinstance(value, dict):
            for v in value.values():
                yield from strings(v)

    for ev in (web, hp, sudo):
        assert all("\x00" not in s for s in strings(ev)), ev
    assert hp["http_status"] is None and web["http_path"] == "/a\\x00b"
