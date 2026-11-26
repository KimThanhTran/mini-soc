import pytest

from app.engine import Engine, haversine_km
from app.rules import _selection, compile_condition, load_rules
from conftest import ev, fired


def test_alert_fires_once_then_stays_quiet_for_the_timespan(engine):
    burst = [ev(i, src_ip="10.3.9.9") for i in range(40)]  # 40 failures in 40 s
    assert fired(engine, burst).count("ssh-brute-force") == 1


def test_fires_again_after_the_quiet_period(engine):
    first = [ev(i) for i in range(10)]
    later = [ev(200 + i) for i in range(10)]
    assert fired(engine, first + later).count("ssh-brute-force") == 2


def test_window_forgets_old_events(engine):
    events = [ev(i) for i in range(9)] + [ev(200 + i) for i in range(9)]  # never 10 inside one minute
    assert "ssh-brute-force" not in fired(engine, events)


def test_sources_are_counted_separately(engine):
    events = [ev(i, src_ip=f"10.3.0.{i}") for i in range(30)]
    assert "ssh-brute-force" not in fired(engine, events)


def test_events_without_the_group_field_are_ignored(engine):
    assert fired(engine, [ev(i, src_ip=None) for i in range(30)]) == []


def test_gc_drops_idle_windows(rules):
    engine = Engine(rules)
    engine.process(ev(0, src_ip="10.3.5.5"))
    assert engine.windows
    engine._gc(ev(10_000)["ts"])
    assert not engine.windows


def test_travel_needs_geo(engine):
    events = [ev(0, outcome="success", user="a", src_ip="192.0.2.1"), ev(60, outcome="success", user="a", src_ip="198.51.100.1")]
    assert "impossible-travel" not in fired(engine, events)


def test_haversine():
    assert haversine_km(10.82, 106.63, 10.82, 106.63) == 0
    assert 1100 < haversine_km(10.82, 106.63, 21.03, 105.85) < 1200  # Ho Chi Minh City to Hanoi


def test_every_selection_modifier():
    e = {"a": "Hello World", "n": 5, "d": {"k": "v"}}
    assert _selection({"a|contains": "WORLD"})(e) and _selection({"a|startswith": "hello"})(e)
    assert _selection({"a|endswith": "world"})(e) and _selection({"a|re": "^H.*d$"})(e)
    assert _selection({"n|gte": 5, "n|lt": 6})(e) and not _selection({"n|gt": 5})(e)
    assert _selection({"a": ["nope", "hello world"]})(e)  # a list is OR
    assert _selection([{"a": "nope"}, {"d.k": "v"}])(e)  # a list of maps is OR
    assert not _selection({"a": "Hello", "n": 5})(e)  # fields are AND
    assert not _selection({"missing": "x"})(e)


def test_condition_grammar():
    sels = {"a": lambda e: e["a"], "b": lambda e: e["b"]}
    run = lambda expr, a, b: compile_condition(expr, sels)({"a": a, "b": b})
    assert run("a and b", True, True) and not run("a and b", True, False)
    assert run("a or b", False, True) and not run("a or b", False, False)
    assert run("a and not b", True, False) and not run("not (a or b)", True, False)
    assert run("not a or b and a", False, False)  # not binds tighter than and, and tighter than or
    for bad in ("a and", "a b", "(a or b", "c", "a or or b"):
        with pytest.raises(ValueError):
            compile_condition(bad, sels)


def test_bad_rules_are_refused(tmp_path):
    base = ("id: x\ntitle: t\ndescription: d\nlevel: high\ntags: {tags}\n"
            "detection:\n  s: {{action: auth}}\n  condition: {cond}\n"
            "correlation: {{type: event_count, group_by: [src_ip], timespan: 1m, threshold: 1}}\nincident_type: t\n")
    for tags, cond in (("[attack.credential_access]", "s"),  # no technique
                       ("[attack.t1110.001]", "s"),  # no tactic
                       ("[attack.credential_access, attack.t9999]", "s"),  # technique the dashboard cannot name
                       ("[attack.credential_access, attack.t1110.001]", "nope")):  # unknown selection
        (tmp_path / "r.yml").write_text(base.format(tags=tags, cond=cond))
        with pytest.raises(ValueError):
            load_rules(tmp_path)


def test_shipped_rules_load():
    assert len(load_rules()) >= 9
