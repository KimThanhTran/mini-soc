from datetime import timedelta

import pytest

from app import incidents
from app.db import AlertRow, make_session_factory
from app.incidents import attach, change_status
from conftest import T0


@pytest.fixture
def db():
    with make_session_factory("sqlite:///:memory:")() as session:
        yield session


def alert(db, seconds=0, ip="10.5.1.1", kind="brute_force", severity="high", user=None):
    a = AlertRow(ts=T0 + timedelta(seconds=seconds), rule_id="r", title="T", severity=severity, techniques=[],
                 incident_type=kind, src_ip=ip, user=user, summary="s", event_ids=[])
    db.add(a)
    db.flush()
    return a, attach(db, a)


def test_alerts_for_one_address_share_an_incident_and_keep_the_highest_severity(db):
    _, first = alert(db, 0, severity="medium")
    _, second = alert(db, 600, kind="web_attack", severity="critical")
    assert first.id == second.id and second.severity == "critical" and second.types == ["brute_force", "web_attack"]
    assert [e["kind"] for e in second.timeline] == ["alert", "alert"]


def test_playbook_has_steps_for_each_type_once(db):
    _, i = alert(db, 0)
    alert(db, 10)  # same type again adds no steps
    steps = [s for s in i.playbook if s["type"] == "brute_force"]
    assert len(steps) == len(incidents.PLAYBOOKS["brute_force"]) == len(i.playbook)
    assert all(not s["done"] for s in i.playbook)


def test_a_quiet_half_hour_or_another_address_opens_a_new_incident(db):
    _, a = alert(db, 0)
    _, b = alert(db, incidents.GROUP_WINDOW_S + 60)
    _, c = alert(db, 0, ip="10.5.2.2")
    assert len({a.id, b.id, c.id}) == 3


def test_closed_incidents_are_not_reused(db):
    _, a = alert(db, 0)
    change_status(a, "closed")
    _, b = alert(db, 30)
    assert a.id != b.id


def test_user_entity_when_there_is_no_address(db):
    _, i = alert(db, 0, ip=None, user="bob", kind="privilege_escalation")
    assert (i.entity, i.entity_kind) == ("bob", "user")


def test_new_activity_reopens_a_contained_incident(db):
    _, i = alert(db, 0)
    change_status(i, "investigating")
    change_status(i, "contained")
    alert(db, 60)
    assert i.status == "investigating" and "new activity after containment" in i.timeline[-1]["text"]


def test_status_life_cycle(db):
    _, i = alert(db, 0)
    for step in ("investigating", "contained", "closed", "investigating"):
        change_status(i, step)
    assert i.status == "investigating"
    assert [e["text"] for e in i.timeline if e["kind"] == "status"][0] == "new -> investigating"


@pytest.mark.parametrize("start,bad", [("new", "contained"), ("new", "new_typo"), ("investigating", "new"), ("closed", "contained")])
def test_illegal_transitions_are_refused(db, start, bad):
    _, i = alert(db, 0)
    i.status = start
    with pytest.raises((ValueError, KeyError)):
        change_status(i, bad)
    assert i.status == start


def test_steps_and_notes_are_recorded_in_the_timeline(db):
    _, i = alert(db, 0)
    incidents.set_step(i, 1, True)
    assert i.playbook[1]["done"] and i.playbook[0]["done"] is False
    incidents.add_note(i, "called the owner")
    incidents.add_note(i, "called the owner")  # unchanged: no second entry
    assert [e["kind"] for e in i.timeline].count("note") == 1
    with pytest.raises(IndexError):
        incidents.set_step(i, 99, True)
