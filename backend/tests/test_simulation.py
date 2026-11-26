"""The simulator's claims, checked: classic attacks trip a rule, slow ones stay under every rule."""
import random
from datetime import datetime, timezone

import pytest

from app.engine import Engine
from app.evaluate import pr
from app.ml import to_event
from app.rules import load_rules
from app.simulation import CLASSIC, EVASIVE, benign

START = datetime(2026, 3, 1, 8, tzinfo=timezone.utc)


def run_rules(items):
    engine = Engine(load_rules())
    events = [to_event(i.raw) for i in sorted(items, key=lambda i: i.ts)]
    for n, e in enumerate(events):
        e["id"] = n
    return [m for e in events for m in engine.process(e)]


@pytest.mark.parametrize("name", sorted(CLASSIC))
def test_classic_attack_trips_a_rule_naming_the_attacker(name):
    items = CLASSIC[name](random.Random(3), START)
    attacker = next(i.actor for i in items if i.actor)
    assert attacker in {m.src_ip for m in run_rules(items)}


@pytest.mark.parametrize("name", ["slow_bruteforce", "slow_scan", "slow_spray"])
def test_slow_attack_stays_under_every_rule(name):
    assert run_rules(EVASIVE[name](random.Random(3), START)) == []


def test_benign_traffic_trips_no_rule_and_is_all_labelled_benign():
    items = benign(random.Random(5), START, 120)
    assert {i.label for i in items} == {"benign"} and len(items) > 1000
    assert run_rules(items) == []


def test_generator_is_deterministic():
    a = [i.raw for i in benign(random.Random(1), START, 10)]
    b = [i.raw for i in benign(random.Random(1), START, 10)]
    assert a == b


def test_precision_recall_helper():
    label = {"a": "x", "b": "x", "c": "benign", "d": "benign"}
    assert pr({"a", "c"}, {"a", "b"}, label) == (0.5, 0.5, 1)
    assert pr(set(), {"a", "b"}, label) == (1.0, 0.0, 0)
