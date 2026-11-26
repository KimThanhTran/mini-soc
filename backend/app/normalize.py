"""Turns raw logs (sshd lines, web access lines, Windows event records, honeypot records) into one event shape."""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from urllib.parse import unquote

from pydantic import BaseModel, Field


class Rejected(ValueError):
    """The record cannot be understood; the API reports it instead of storing guesses."""


class RawEvent(BaseModel):
    source: str = Field(pattern=r"^(ssh|web|windows|honeypot_ssh|honeypot_web)$")
    ts: datetime | None = None
    host: str = Field(default="unknown", max_length=255)
    message: str | None = Field(default=None, max_length=2000)  # a log line (ssh, web)
    data: dict | None = None  # a structured record (windows, honeypots)


SSH_FAILED = re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+")
SSH_OK = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+) port \d+")
SUDO = re.compile(r"sudo:\s+(?P<user>\S+) : .*?USER=(?P<target>\S+) ; COMMAND=(?P<cmd>.+)$")
WEB = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" '
    r'(?P<status>\d{3}) \S+(?: "[^"]*" "(?P<ua>[^"]*)")?'
)

# Demo geolocation: the simulator uses synthetic 10.<region>.x.x addresses. A real deployment would query a GeoIP database.
GEO_DEMO = {
    "10.1.": ("VN", 10.82, 106.63), "10.2.": ("VN", 21.03, 105.85), "10.3.": ("DE", 52.52, 13.40),
    "10.4.": ("US", 40.71, -74.01), "10.5.": ("RU", 55.76, 37.62), "10.6.": ("BR", -23.55, -46.63),
    "10.7.": ("CN", 39.90, 116.40), "10.8.": ("NG", 6.52, 3.38),
}


def geo_lookup(ip: str | None):
    return next((g for prefix, g in GEO_DEMO.items() if ip and ip.startswith(prefix)), (None, None, None))


def _ip(value) -> str | None:
    if value in (None, "", "-"):
        return None
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        raise Rejected(f"not an IP address: {str(value)[:40]!r}") from None


def _clean(text: str) -> str:
    """PostgreSQL refuses NUL in text; an attacker can send one as %00, so it is kept as the visible four characters \\x00."""
    return text.replace("\x00", "\\x00")


def _s(value, limit: int) -> str | None:
    return None if value in (None, "", "-") else _clean(str(value))[:limit]


def _decode(path: str) -> str:
    """Decodes percent-escapes twice so %252e%252e/ cannot hide a traversal; the raw path is kept in extra."""
    return _clean(unquote(unquote(path)))[:2000]


def _base(raw: dict, **fields) -> dict:
    ts = raw["ts"] or datetime.now(timezone.utc)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    ev = dict(ts=ts, source=raw["source"], host=_clean(raw["host"]), src_ip=None, user=None, action="other", outcome=None,
              http_method=None, http_path=None, http_status=None, user_agent=None, extra={})
    ev.update(fields)
    ev["geo_country"], ev["geo_lat"], ev["geo_lon"] = geo_lookup(ev["src_ip"])
    return ev


def _ssh(raw: dict) -> dict:
    msg = raw.get("message") or ""
    if m := SSH_FAILED.search(msg):
        return _base(raw, src_ip=_ip(m["ip"]), user=_s(m["user"], 128), action="auth", outcome="failure")
    if m := SSH_OK.search(msg):
        return _base(raw, src_ip=_ip(m["ip"]), user=_s(m["user"], 128), action="auth", outcome="success")
    if m := SUDO.search(msg):
        return _base(raw, user=_s(m["user"], 128), action="sudo",
                     extra={"target_user": _s(m["target"], 64), "command": _s(m["cmd"], 300)})
    raise Rejected("unrecognised sshd line")


def _web(raw: dict) -> dict:
    m = WEB.match(raw.get("message") or "")
    if not m:
        raise Rejected("not a combined-format access log line")
    return _base(raw, src_ip=_ip(m["ip"]), user=_s(m["user"], 128), action="http_request", http_method=m["method"],
                 http_path=_decode(m["path"]), http_status=int(m["status"]), user_agent=_s(m["ua"], 300),
                 extra={"raw_path": _s(m["path"], 2000)})


def _windows(raw: dict) -> dict:
    d = raw.get("data") or {}
    try:
        eid = int(d.get("EventID"))
    except (TypeError, ValueError):
        raise Rejected("missing EventID") from None
    ip = _ip(d.get("IpAddress"))
    if eid == 4625:
        return _base(raw, src_ip=ip, user=_s(d.get("TargetUserName"), 128), action="auth", outcome="failure")
    if eid == 4624:
        return _base(raw, src_ip=ip, user=_s(d.get("TargetUserName"), 128), action="auth", outcome="success",
                     extra={"logon_type": _s(d.get("LogonType"), 16)})
    if eid == 4732:  # a member was added to a security-enabled local group
        return _base(raw, user=_s(d.get("SubjectUserName"), 128), action="group_add",
                     extra={"group": _s(d.get("TargetUserName"), 128), "member": _s(d.get("MemberName"), 128)})
    raise Rejected(f"unsupported Windows EventID {eid}")


def _honeypot_ssh(raw: dict) -> dict:
    d = raw.get("data") or {}
    return _base(raw, src_ip=_ip(d.get("src_ip")), user=_s(d.get("user"), 128), action="auth", outcome="failure",
                 extra={"password": _s(d.get("password"), 64)})


def _honeypot_web(raw: dict) -> dict:
    d = raw.get("data") or {}
    path = _decode(str(d.get("path", "/")))
    common = dict(src_ip=_ip(d.get("src_ip")), http_method=_s(d.get("method"), 16), http_path=path,
                  http_status=d["status"] if isinstance(d.get("status"), int) and 100 <= d["status"] <= 599 else None,
                  user_agent=_s(d.get("user_agent"), 300))
    if d.get("username") is not None:  # a credential was posted to the fake login form
        return _base(raw, **common, user=_s(d.get("username"), 128), action="auth", outcome="failure",
                     extra={"password": _s(d.get("password"), 64)})
    return _base(raw, **common, action="http_request")


PARSERS = {"ssh": _ssh, "web": _web, "windows": _windows, "honeypot_ssh": _honeypot_ssh, "honeypot_web": _honeypot_web}


def normalize(raw: dict, check_time: bool = True) -> dict:
    """raw is RawEvent.model_dump(). Raises Rejected for anything it cannot interpret."""
    ev = PARSERS[raw["source"]](raw)
    now = datetime.now(timezone.utc)
    if check_time and not (-7 * 86400 < (ev["ts"] - now).total_seconds() < 300):
        raise Rejected("timestamp outside the accepted range (7 days back, 5 minutes ahead)")
    return ev
