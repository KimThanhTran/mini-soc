"""Streaming rule engine: keeps sliding windows in memory and returns a Match when a rule's correlation is satisfied.

Time comes from the events, not the wall clock, so replays and tests are deterministic.
"""
from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .rules import Rule, get_field

WINDOW_CAP = 5000  # shortcut: a window keeps its newest 5000 events, so thresholds above that never fire
GC_EVERY = 5000


@dataclass
class Match:
    rule: Rule
    ts: datetime
    src_ip: str | None
    user: str | None
    summary: str
    event_ids: list[int] = field(default_factory=list)


def haversine_km(lat1, lon1, lat2, lon2) -> float:
    p1, p2 = math.radians(lat1), math.radians(lat2)
    a = math.sin((p2 - p1) / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(math.radians(lon2 - lon1) / 2) ** 2
    return 12742 * math.asin(math.sqrt(a))


class Engine:
    def __init__(self, rules: list[Rule]):
        self.rules = rules
        self.windows: dict[tuple, deque] = {}
        self.quiet_until: dict[tuple, datetime] = {}  # after an alert the same rule and key stay quiet for one timespan
        self.last_login: dict[tuple, tuple] = {}
        self._seen = 0

    def process(self, ev: dict) -> list[Match]:
        matches = [m for rule in self.rules if (m := self._run(rule, ev))]
        self._seen += 1
        if self._seen % GC_EVERY == 0:
            self._gc(ev["ts"])
        return matches

    def _gc(self, now: datetime) -> None:
        spans = {r.id: r.correlation.timespan for r in self.rules}
        for key in [k for k, dq in self.windows.items() if not dq or (now - dq[-1][0]).total_seconds() > spans[k[0]]]:
            del self.windows[key]
        for key in [k for k, until in self.quiet_until.items() if until < now]:
            del self.quiet_until[key]

    def _fire(self, rule: Rule, key: tuple, ev: dict, summary: str, ids: list[int], src_ip=None, user=None) -> Match:
        self.quiet_until[(rule.id, key)] = ev["ts"] + timedelta(seconds=rule.correlation.cooldown or rule.correlation.timespan)
        self.windows.pop((rule.id, key), None)
        return Match(rule, ev["ts"], src_ip or ev.get("src_ip"), user or ev.get("user"), summary, ids[-20:])

    def _run(self, rule: Rule, ev: dict) -> Match | None:
        c = rule.correlation
        key = tuple(get_field(ev, f) for f in c.group_by)
        if None in key:
            return None
        if self.quiet_until.get((rule.id, key), ev["ts"]) > ev["ts"]:
            return None
        if c.type == "temporal":
            return self._temporal(rule, key, ev)
        if not rule.matches(ev):
            return None
        if c.type == "impossible_travel":
            return self._travel(rule, key, ev)
        value = get_field(ev, c.value_field) if c.type == "value_count" else None
        if c.type == "value_count" and value is None:
            return None
        window = self._window(rule, key, ev["ts"], (ev["ts"], ev.get("id"), value))
        count = len({w[2] for w in window}) if c.type == "value_count" else len(window)
        if count < c.threshold:
            return None
        what = f"{count} distinct {c.value_field}" if c.type == "value_count" else f"{count} matching events"
        return self._fire(rule, key, ev, f"{what} for {', '.join(map(str, key))} within {c.timespan}s",
                          [w[1] for w in window if w[1] is not None])

    def _window(self, rule: Rule, key: tuple, now: datetime, item: tuple) -> deque:
        window = self.windows.setdefault((rule.id, key), deque(maxlen=WINDOW_CAP))
        window.append(item)
        while window and (now - window[0][0]).total_seconds() > rule.correlation.timespan:
            window.popleft()
        return window

    def _temporal(self, rule: Rule, key: tuple, ev: dict) -> Match | None:
        first, second = rule._steps
        window = self.windows.setdefault((rule.id, key), deque(maxlen=WINDOW_CAP))
        span = rule.correlation.timespan
        if second(ev):
            for ts, ev_id, ip in reversed(window):
                if 0 <= (ev["ts"] - ts).total_seconds() <= span:
                    who = ", ".join(map(str, key))
                    return self._fire(rule, key, ev, f"{who}: privileged action {int((ev['ts'] - ts).total_seconds())}s "
                                      f"after a login", [ev_id, ev.get("id")], src_ip=ip)
        elif first(ev):
            window.append((ev["ts"], ev.get("id"), ev.get("src_ip")))
        return None

    def _travel(self, rule: Rule, key: tuple, ev: dict) -> Match | None:
        if ev.get("geo_lat") is None:
            return None
        c = rule.correlation
        here = (ev["ts"], ev["geo_country"], ev["geo_lat"], ev["geo_lon"], ev.get("src_ip"), ev.get("id"))
        prev = self.last_login.get((rule.id, key))
        self.last_login[(rule.id, key)] = here
        if not prev or prev[1] == here[1]:
            return None
        km = haversine_km(prev[2], prev[3], here[2], here[3])
        hours = max((here[0] - prev[0]).total_seconds(), 1) / 3600
        if km < c.min_distance_km or km / hours <= c.max_speed_kmh:
            return None
        return self._fire(rule, key, ev, f"{key[0]} logged in from {prev[1]} ({prev[4]}) and {int(hours * 60)} min later "
                          f"from {here[1]} ({here[4]}): {int(km)} km, {int(km / hours)} km/h", [prev[5], here[5]])
