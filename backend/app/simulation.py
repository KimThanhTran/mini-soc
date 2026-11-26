"""Synthetic traffic: a benign background and labelled attack scenarios. Standard library only, because the simulator
image copies this single file. All addresses are synthetic 10.<region>.x.x ones (region 1-2 inside the company, 3-8 abroad)."""
from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import datetime, timedelta

USERS = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan", "judy", "ken", "lena", "mike",
         "nina", "omar", "pia"]
VICTIMS = [f"contractor{n:02d}" for n in range(1, 21)]  # accounts the benign traffic never uses, so labels do not collide
PATHS_OK = ["/", "/index.html", "/static/app.js", "/static/app.css", "/api/tickets", "/api/tickets/42", "/dashboard",
            "/reports", "/api/profile", "/favicon.ico"]
SCAN_WORDS = ["admin", "wp-login.php", "phpmyadmin/", ".env", ".git/config", "backup.zip", "config.php", "server-status",
              "console", "manager/html", "api/v1/users", "old", "test", "db.sql", "login.php", "xmlrpc.php", "setup.php"]
UA_BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36"
UA_BOT = "Mozilla/5.0 (compatible; uptime-monitor/2.1)"
UA_SCANNER = "Mozilla/5.0 (compatible; probe/1.0)"
SSH_HOST, WEB_HOST, WIN_HOST = "bastion-01", "intranet-web", "dc-01"


@dataclass
class Item:
    raw: dict  # what a log shipper would send to /api/ingest
    ts: datetime
    actor: str | None  # the source address the label is about (None: not part of the ground truth)
    label: str  # "benign" or the scenario name


def ip_in(rng: random.Random, region: int) -> str:
    return f"10.{region}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _ssh(ts, msg, actor, label):
    return Item({"source": "ssh", "ts": ts.isoformat(), "host": SSH_HOST, "message": f"sshd[2211]: {msg}"}, ts, actor, label)


def ssh_fail(rng, ts, ip, user, label, invalid=False):
    who = f"invalid user {user}" if invalid else user
    return _ssh(ts, f"Failed password for {who} from {ip} port {rng.randint(20000, 60000)} ssh2", ip, label)


def ssh_ok(rng, ts, ip, user, label):
    return _ssh(ts, f"Accepted password for {user} from {ip} port {rng.randint(20000, 60000)} ssh2", ip, label)


def sudo(ts, user, cmd, actor, label):
    return Item({"source": "ssh", "ts": ts.isoformat(), "host": SSH_HOST,
                 "message": f"sudo:   {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}"}, ts, actor, label)


def web(rng, ts, ip, path, status, label, ua=UA_BROWSER, method="GET"):
    line = f'{ip} - - [{ts:%d/%b/%Y:%H:%M:%S +0000}] "{method} {path} HTTP/1.1" {status} {rng.randint(200, 9000)} "-" "{ua}"'
    return Item({"source": "web", "ts": ts.isoformat(), "host": WEB_HOST, "message": line}, ts, ip, label)


def win(ts, eid, ip, label, **data):
    return Item({"source": "windows", "ts": ts.isoformat(), "host": WIN_HOST,
                 "data": {"EventID": eid, "IpAddress": ip, **data}}, ts, ip, label)


def _at(start, seconds):
    return start + timedelta(seconds=seconds)


# ---------------------------------------------------------------- benign

def benign(rng: random.Random, start: datetime, minutes: int) -> list[Item]:
    out: list[Item] = []
    hours = max(minutes / 60, 0.1)
    span = minutes * 60

    for user in USERS:
        ip = ip_in(rng, rng.choice([1, 2]))
        for _ in range(max(1, round(hours * rng.uniform(1, 3)))):
            t = _at(start, rng.uniform(0, span))
            kind = rng.choices(["ssh", "web", "win"], [4, 5, 2])[0]
            if kind == "ssh":
                for _ in range(rng.choices([0, 1, 2, 3, 4], [70, 15, 8, 5, 2])[0]):  # typos before the right password
                    out.append(ssh_fail(rng, t, ip, user, "benign"))
                    t += timedelta(seconds=rng.uniform(3, 10))
                out.append(ssh_ok(rng, t, ip, user, "benign"))
                if rng.random() < 0.2:
                    out.append(sudo(t + timedelta(seconds=rng.uniform(60, 300)), user, "/usr/bin/apt update", ip, "benign"))
            elif kind == "web":
                for _ in range(rng.randint(5, 40)):
                    t += timedelta(seconds=rng.uniform(1, 8))
                    status = rng.choices([200, 304, 302, 404], [85, 8, 4, 3])[0]
                    out.append(web(rng, t, ip, rng.choice(PATHS_OK), status, "benign"))
            else:
                for _ in range(rng.choices([0, 1, 2], [80, 15, 5])[0]):
                    out.append(win(t, 4625, ip, "benign", TargetUserName=user))
                    t += timedelta(seconds=5)
                out.append(win(t, 4624, ip, "benign", TargetUserName=user, LogonType=3))

    for _ in range(2):  # crawlers: many requests, nearly all fine
        ip = ip_in(rng, 1)
        for _ in range(max(1, round(hours / 2))):
            t = _at(start, rng.uniform(0, max(span - 600, 1)))
            for _ in range(200):
                t += timedelta(seconds=3)
                out.append(web(rng, t, ip, rng.choice(PATHS_OK), rng.choices([200, 404], [98, 2])[0], "benign", UA_BOT))

    ip = ip_in(rng, 1)  # uptime monitor
    for m in range(minutes):
        out.append(web(rng, _at(start, m * 60 + rng.uniform(0, 5)), ip, "/healthz", 200, "benign", UA_BOT))

    ip = ip_in(rng, 2)  # link checker: some broken links, but modest volume
    t = _at(start, rng.uniform(0, max(span - 600, 1)))
    for _ in range(60):
        t += timedelta(seconds=10)
        out.append(web(rng, t, ip, f"/docs/{rng.choice(SCAN_WORDS)}", rng.choices([200, 404], [70, 30])[0], "benign", UA_BOT))

    ip = ip_in(rng, 2)  # a misconfigured service account failing about once a minute for 20 minutes
    t = _at(start, rng.uniform(0, max(span - 1200, 1)))
    for _ in range(20):
        t += timedelta(seconds=rng.uniform(50, 90))
        out.append(ssh_fail(rng, t, ip, "svc-backup", "benign"))
    return [i for i in out if i.ts < start + timedelta(minutes=minutes + 30)]


# ---------------------------------------------------------------- attacks that the rules catch

def _attacker(rng):
    return ip_in(rng, rng.randint(3, 8))


def ssh_bruteforce(rng, start):
    ip, t, out = _attacker(rng), start, []
    for _ in range(40):
        user = rng.choice(["root", "admin", "ubuntu", "test", "oracle", "postgres"])
        out.append(ssh_fail(rng, t, ip, user, "ssh_bruteforce", invalid=user != "root"))
        t += timedelta(seconds=rng.uniform(0.8, 1.4))
    return out


def password_spray(rng, start):
    ip, t, out = _attacker(rng), start, []
    for user in rng.sample(USERS + ["guest", "info", "support", "sales"], 12):
        out.append(ssh_fail(rng, t, ip, user, "password_spray", invalid=user not in USERS))
        t += timedelta(seconds=rng.uniform(8, 15))
    return out


def impossible_travel(rng, start):
    user, home, away = rng.choice(VICTIMS), ip_in(rng, 1), ip_in(rng, rng.choice([5, 6, 7]))
    first = ssh_ok(rng, start, home, user, "impossible_travel")
    first.actor = None
    return [first, ssh_ok(rng, _at(start, 1200), away, user, "impossible_travel")]


def web_scan(rng, start):
    ip, t, out = _attacker(rng), start, []
    for n in range(80):
        out.append(web(rng, t, ip, f"/{rng.choice(SCAN_WORDS)}{rng.randint(0, 999)}", 404, "web_scan", UA_SCANNER))
        t += timedelta(seconds=rng.uniform(0.3, 0.7))
    return out


def sqli_probe(rng, start):
    ip, out = _attacker(rng), []
    for n, path in enumerate(["/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users--",
                              "/search?q=%27%20OR%20%271%27=%271", "/item?id=1%20OR%201=1",
                              "/items?id=1;SELECT%20SLEEP(5)--", "/p?id=1%20UNION%20SELECT%20table_name%20FROM%20information_schema.tables"]):
        out.append(web(rng, _at(start, n * 3), ip, path, rng.choice([200, 500]), "sqli_probe", UA_SCANNER))
    return out


def path_traversal(rng, start):
    ip, out = _attacker(rng), []
    for n, path in enumerate(["/download?file=../../../../etc/passwd", "/static/..%2f..%2f..%2fetc/passwd",
                              "/img?f=..%252f..%252fetc%252fpasswd", "/files/..\\..\\windows\\win.ini"]):
        out.append(web(rng, _at(start, n * 2), ip, path, rng.choice([400, 403, 404]), "path_traversal", UA_SCANNER))
    return out


def priv_esc(rng, start):
    ip, user, out = ip_in(rng, 5), rng.choice(VICTIMS), []
    if rng.random() < 0.5:
        for n in range(3):
            out.append(ssh_fail(rng, _at(start, n * 4), ip, user, "priv_esc"))
        out.append(ssh_ok(rng, _at(start, 14), ip, user, "priv_esc"))
        shell = sudo(_at(start, 134), user, "/bin/bash", None, "priv_esc")
        out.append(shell)
    else:
        out.append(win(start, 4624, ip, "priv_esc", TargetUserName=user, LogonType=10))
        out.append(win(_at(start, 90), 4732, None, "priv_esc", SubjectUserName=user, TargetUserName="Administrators", MemberName=user))
        out[-1].actor = None
    return out


# ---------------------------------------------------------------- slow attacks: built to stay under the rule thresholds

def slow_bruteforce(rng, start):  # 4 failures a minute for 8 minutes: never 10 in one minute
    ip = _attacker(rng)
    return [ssh_fail(rng, _at(start, n * 15), ip, rng.choice(["root", "admin"]), "slow_bruteforce") for n in range(32)]


def slow_spray(rng, start):  # one attempt a minute, 12 usernames: at most 6 distinct in any five minutes
    ip = _attacker(rng)
    names = rng.sample(USERS + ["guest", "info", "support", "sales"], 12)
    return [ssh_fail(rng, _at(start, n * 60), ip, u, "slow_spray", invalid=u not in USERS) for n, u in enumerate(names)]


def slow_scan(rng, start):  # 10 distinct 404 paths a minute: never 15 in one minute
    ip = _attacker(rng)
    return [web(rng, _at(start, n * 6), ip, f"/{rng.choice(SCAN_WORDS)}{rng.randint(0, 9999)}", 404, "slow_scan", UA_SCANNER)
            for n in range(80)]


CLASSIC = {f.__name__: f for f in (ssh_bruteforce, password_spray, impossible_travel, web_scan, sqli_probe, path_traversal, priv_esc)}
EVASIVE = {f.__name__: f for f in (slow_bruteforce, slow_spray, slow_scan)}
SCENARIOS = {**CLASSIC, **EVASIVE}
