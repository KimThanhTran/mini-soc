import random
from datetime import datetime, timezone

import pytest

from app import simulation
from app.ml import MIN_EVENTS, features, replay, to_event, train_default
from conftest import ev, http


@pytest.fixture(scope="module")
def scorer():
    return train_default()


def test_features():
    events = [ev(i, user="a") for i in range(5)] + [ev(9, outcome="success", user="b")] + [
        http(i, "/x", 404 if i < 3 else 200) for i in range(10)]
    failed, users, req, err = features(events)
    assert (failed, users, req, err) == (1.0, 2.0, 2.0, 0.3)


def test_too_little_activity_is_not_scored():
    assert features([ev(i) for i in range(MIN_EVENTS - 1)]) is None
    assert features([]) is None


def test_replay_yields_trailing_windows_per_source_and_forgets_old_events():
    events = [ev(i * 10, src_ip="10.3.0.1") for i in range(30)] + [ev(i * 10, src_ip="10.3.0.2") for i in range(3)]
    windows = list(replay(events))
    assert {ip for _, ip, _ in windows} == {"10.3.0.1"}  # the quiet source never reaches MIN_EVENTS
    assert max(vec[0] for _, _, vec in windows) <= 30 / 5  # failed per minute never exceeds the window's 5 minutes


def flagged(scorer, items):
    events = [to_event(i.raw) for i in items]
    return {ip for ip, s in ((ip, scorer.score([v])[0]) for _, ip, v in replay(events)) if s < 0}


def test_slow_attacks_are_flagged_and_most_benign_sources_are_not(scorer):
    rng = random.Random(7)
    start = datetime(2026, 3, 1, 8, tzinfo=timezone.utc)
    benign_items = simulation.benign(rng, start, 60)
    benign_ips = {i.actor for i in benign_items if i.actor}
    assert len(flagged(scorer, benign_items) & benign_ips) <= 0.1 * len(benign_ips)
    for make in (simulation.slow_bruteforce, simulation.slow_scan):
        attack = make(rng, start)
        assert flagged(scorer, attack) == {attack[0].actor}, make.__name__


def test_scorer_is_deterministic():
    a, b = train_default(hours=1), train_default(hours=1)
    probe = [[3.0, 4, 1.0, 0.5]]
    assert a.score(probe) == b.score(probe)
