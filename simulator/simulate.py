"""Reproducible demo traffic for mini-soc: benign history, labelled attacks sent to the ingestion API, and attempts
against the two honeypots. It refuses to talk to anything that is not on a private or loopback address.

    python simulate.py --api http://api:8000 --ssh-host ssh-honeypot --web http://web-honeypot:8080
"""
import argparse
import asyncio
import ipaddress
import json
import os
import random
import socket
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

import httpx

# repo layout; the image copies these files flat next to this one
sys.path[:0] = [str(Path(__file__).resolve().parents[1] / "sensors"), str(Path(__file__).resolve().parents[1] / "backend" / "app")]
from simulation import SCENARIOS, benign, ip_in  # noqa: E402

from ship import signed_headers  # noqa: E402

SSH_USERS = ["root", "admin", "ubuntu", "pi", "oracle", "test"]
SSH_PASSWORDS = ["123456", "password", "admin", "root", "toor", "qwerty", "letmein", "changeme"]
WEB_PROBES = ["/admin", "/wp-login.php", "/phpmyadmin/", "/.env", "/.git/config", "/backup.zip", "/config.php", "/server-status",
              "/console", "/manager/html", "/xmlrpc.php", "/setup.php", "/db.sql", "/old/", "/test/", "/api/v1/users",
              "/cgi-bin/", "/login.php", "/administrator", "/robots.txt"]


def assert_private(host: str) -> None:
    """Safety rail: every address the name resolves to must be private or loopback, or nothing is sent."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        sys.exit(f"refusing to send traffic to {host}: it does not resolve here, so it cannot be shown to be private")
    for info in infos:
        if not ipaddress.ip_address(info[4][0]).is_private:
            sys.exit(f"refusing to send traffic to {host} ({info[4][0]}): not a private address")


def shifted(items, now):
    """Moves a scenario in time so that its last event is 'now'."""
    delta = now - max(i.ts for i in items)
    for i in items:
        i.ts += delta
        i.raw["ts"] = i.ts.isoformat()
    return sorted(items, key=lambda i: i.ts)


def post(client, api, sensor, secret, raws):
    for n in range(0, len(raws), 400):
        body = json.dumps({"events": raws[n:n + 400]}).encode()
        r = client.post(f"{api}/api/ingest", content=body, headers=signed_headers(sensor, secret, body))
        r.raise_for_status()
        info = r.json()
        if info["rejected"]:
            print("  rejected:", info["rejected"][:3])
        yield info


async def ssh_attempts(host, port, rng, count):
    import asyncssh
    sent = 0
    for _ in range(count):
        try:
            async with await asyncssh.connect(host, port, username=rng.choice(SSH_USERS), password=rng.choice(SSH_PASSWORDS),
                                              known_hosts=None, client_keys=None, agent_path=None, login_timeout=10):
                pass
        except asyncssh.PermissionDenied:
            sent += 1  # the decoy always says no
        except (OSError, asyncssh.Error) as e:
            print("  ssh honeypot unreachable:", e)
            break
        await asyncio.sleep(0.2)
    return sent


def web_attempts(base, rng):
    sent = 0
    with httpx.Client(timeout=5) as c:
        for region in rng.sample(range(3, 9), 3):  # three pretend attackers (the lab honeypot trusts X-Forwarded-For)
            h = {"X-Forwarded-For": ip_in(rng, region), "User-Agent": "Mozilla/5.0 (compatible; probe/1.0)"}
            for path in rng.sample(WEB_PROBES, 18):
                c.get(base + path, headers=h)
                sent += 1
            for _ in range(5):
                c.post(base + "/login", data={"username": rng.choice(SSH_USERS), "password": rng.choice(SSH_PASSWORDS)}, headers=h)
                sent += 1
            for path in ("/search?q=1' OR '1'='1", "/download?file=../../../../etc/passwd"):
                c.get(base + path, headers=h)
                sent += 1
    return sent


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--api", default=os.environ.get("API_URL", "http://api:8000"))
    ap.add_argument("--sensor-id", default=os.environ.get("SENSOR_ID", "simulator"))
    ap.add_argument("--ssh-host", default=os.environ.get("SSH_HONEYPOT_HOST"))
    ap.add_argument("--ssh-port", type=int, default=2222)
    ap.add_argument("--web", default=os.environ.get("WEB_HONEYPOT_URL"))
    ap.add_argument("--history", type=int, default=60, help="minutes of benign history to backfill")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--pace", type=float, default=3.0, help="seconds between attack scenarios, so a dashboard can be watched")
    args = ap.parse_args()
    secret = os.environ["SENSOR_SECRET"]
    rng = random.Random(args.seed)

    for target in (urlparse(args.api).hostname, args.ssh_host, urlparse(args.web).hostname if args.web else None):
        if target:
            assert_private(target)

    now = datetime.now(timezone.utc)
    with httpx.Client(timeout=30) as client:
        history = [i for i in benign(rng, now - timedelta(minutes=args.history), args.history) if i.ts <= now]
        history.sort(key=lambda i: i.ts)
        total = sum(r["accepted"] for r in post(client, args.api, args.sensor_id, secret, [i.raw for i in history]))
        print(f"benign history: {total} events over {args.history} min")
        for name, make in SCENARIOS.items():
            items = shifted(make(rng, now), datetime.now(timezone.utc))
            res = list(post(client, args.api, args.sensor_id, secret, [i.raw for i in items]))
            print(f"{name:18s} sent {len(items):3d} events, {sum(r['alerts'] for r in res)} rule alerts")
            time.sleep(args.pace)
    if args.ssh_host:
        print("ssh honeypot: rejected attempts:", asyncio.run(ssh_attempts(args.ssh_host, args.ssh_port, rng, 16)))
    if args.web:
        print("web honeypot: requests sent:", web_attempts(args.web.rstrip("/"), rng))


if __name__ == "__main__":
    main()
