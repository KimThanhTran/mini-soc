"""Every shipped rule has a positive and a negative case here, and the test fails if a rule is added without them."""
import pytest

from app.attack import TECHNIQUES
from conftest import ev, fired, http


def login(user, seconds=0, outcome="success", **kw):
    return ev(seconds, outcome=outcome, user=user, **kw)


def sudo(seconds, command, user="bob"):
    return ev(seconds, action="sudo", outcome=None, user=user, src_ip=None, extra={"target_user": "root", "command": command})


def logins(count, gap, user="root", ip="10.3.1.1"):
    return [ev(i * gap, user=user, src_ip=ip) for i in range(count)]


CASES = {
    "ssh-brute-force": (
        lambda: logins(10, 1),
        [lambda: logins(9, 1), lambda: logins(10, 10), lambda: [e | {"outcome": "success"} for e in logins(10, 1)]]),
    "password-spraying": (
        lambda: [ev(i * 20, user=f"user{i}") for i in range(8)],
        [lambda: [ev(i * 20, user=f"user{i}") for i in range(7)], lambda: [ev(i * 100, user=f"user{i}") for i in range(8)]]),
    "impossible-travel": (
        lambda: [ev(0, outcome="success", user="alice", src_ip="10.1.4.4"),
                 ev(1200, outcome="success", user="alice", src_ip="10.6.9.9")],
        [lambda: [ev(0, outcome="success", user="alice", src_ip="10.1.4.4"),  # same country, other city
                  ev(1200, outcome="success", user="alice", src_ip="10.2.9.9")],
         lambda: [ev(0, outcome="success", user="alice", src_ip="10.1.4.4"),  # far away but a day later
                  ev(86400, outcome="success", user="alice", src_ip="10.6.9.9")],
         lambda: [ev(0, outcome="failure", user="alice", src_ip="10.1.4.4"),  # failures are not logins
                  ev(1200, outcome="failure", user="alice", src_ip="10.6.9.9")]]),
    "web-scanning": (
        lambda: [http(i, f"/p{i}", 404) for i in range(15)],
        [lambda: [http(i, f"/p{i}", 404) for i in range(14)], lambda: [http(i, "/same", 404) for i in range(30)],
         lambda: [http(i, f"/p{i}", 200) for i in range(30)]]),
    "web-sqli-probe": (
        lambda: [http(0, "/items?id=1 UNION SELECT username,password FROM users")],
        [lambda: [http(0, "/items?id=7")], lambda: [http(0, "/search?q=union+station+select+seats")],
         lambda: [ev(0, action="auth")]]),
    "web-path-traversal": (
        lambda: [http(0, "/download?file=../../../etc/passwd")],
        [lambda: [http(0, "/docs/readme.txt")], lambda: [http(0, "/img/logo.png?v=2")]]),
    "priv-esc-after-login": (
        lambda: [login("bob"), sudo(120, "/bin/bash")],
        [lambda: [sudo(0, "/bin/bash")],  # no login before it
         lambda: [login("bob"), sudo(60, "/usr/bin/apt update")],  # an ordinary admin task
         lambda: [login("bob"), sudo(660, "/bin/bash")],  # too long after the login
         lambda: [login("bob"), sudo(60, "/bin/bash", user="carol")],  # a different account
         lambda: [login("bob", outcome="failure"), sudo(60, "/bin/bash")]]),  # a failed login is not a login
    "honeypot-ssh-contact": (
        lambda: [ev(0, source="honeypot_ssh")],
        [lambda: [ev(0, source="ssh")], lambda: [ev(0, source="honeypot_web")]]),
    "honeypot-web-contact": (
        lambda: [http(0, "/admin") | {"source": "honeypot_web"}],
        [lambda: [http(0, "/admin")], lambda: [ev(0, source="honeypot_ssh")]]),
}


def test_every_rule_has_cases(rules):
    assert {r.id for r in rules} == set(CASES)


def test_every_rule_maps_to_known_attack_techniques(rules):
    for r in rules:
        assert r.techniques and r.tactics, r.id
        assert set(r.techniques) <= set(TECHNIQUES), r.id


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_positive(engine, rule_id):
    positive, _ = CASES[rule_id]
    assert rule_id in fired(engine, positive())


@pytest.mark.parametrize("rule_id,index", [(r, i) for r, (_, negs) in sorted(CASES.items()) for i in range(len(negs))])
def test_negative(engine, rule_id, index):
    _, negatives = CASES[rule_id]
    assert rule_id not in fired(engine, negatives[index]())


def test_priv_esc_alert_names_the_login_address(engine):
    first, second = login("bob", src_ip="10.5.7.7"), sudo(90, "sudo -i; /bin/bash")
    matches = [m for e in (first, second) for m in engine.process(e) if m.rule.id == "priv-esc-after-login"]
    assert matches and matches[0].src_ip == "10.5.7.7" and matches[0].event_ids == [first["id"], second["id"]]


def test_windows_admin_group_add_after_logon(engine):
    events = [ev(0, outcome="success", user="eve", source="windows"),
              ev(60, action="group_add", outcome=None, user="eve", src_ip=None, extra={"group": "Administrators", "member": "eve"})]
    assert "priv-esc-after-login" in fired(engine, events)
