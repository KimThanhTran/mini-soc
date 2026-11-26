"""Sigma-style rules: YAML files with named selections, a condition over them, and a correlation block.

A selection maps fields to values. Fields are ANDed, a list of values is ORed, and a modifier after `|` changes the
comparison: contains, startswith, endswith, re, gte, gt, lte, lt. Strings compare case-insensitively. A selection that is
a list of maps is ORed. The condition combines selection names with and / or / not and parentheses.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Callable, Literal

import yaml
from pydantic import BaseModel, PrivateAttr, field_validator, model_validator

from .attack import TACTICS, TECHNIQUES

RULES_DIR = Path(__file__).parent / "rules"
TACTIC_IDS = {t for t, _ in TACTICS}
_TOKEN = re.compile(r"\(|\)|\w+")


def get_field(ev: dict, path: str):
    cur = ev
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _compare(actual, mod: str | None, expected) -> bool:
    if actual is None:
        return False
    if mod in ("gte", "gt", "lte", "lt"):
        try:
            a, e = float(actual), float(expected)
        except (TypeError, ValueError):
            return False
        return {"gte": a >= e, "gt": a > e, "lte": a <= e, "lt": a < e}[mod]
    if mod == "re":
        return re.search(str(expected), str(actual), re.IGNORECASE) is not None
    a, e = str(actual).lower(), str(expected).lower()
    return {None: a == e, "contains": e in a, "startswith": a.startswith(e), "endswith": a.endswith(e)}[mod]


def _selection(spec) -> Callable[[dict], bool]:
    if isinstance(spec, list):
        subs = [_selection(s) for s in spec]
        return lambda ev: any(s(ev) for s in subs)
    tests = []
    for key, expected in spec.items():
        name, _, mod = key.partition("|")
        if mod not in ("", "contains", "startswith", "endswith", "re", "gte", "gt", "lte", "lt"):
            raise ValueError(f"unknown modifier {mod!r} in {key!r}")
        options = expected if isinstance(expected, list) else [expected]
        if mod == "re":
            for pattern in options:
                re.compile(str(pattern))
        tests.append((name, mod or None, options))
    return lambda ev: all(any(_compare(get_field(ev, n), m, o) for o in opts) for n, m, opts in tests)


def compile_condition(expr: str, selections: dict[str, Callable]) -> Callable[[dict], bool]:
    tokens = _TOKEN.findall(expr)
    pos = 0

    def peek():
        return tokens[pos] if pos < len(tokens) else None

    def take():
        nonlocal pos
        pos += 1
        return tokens[pos - 1]

    def parse_or():
        node = parse_and()
        while peek() == "or":
            take()
            node = (lambda a, b: lambda ev: a(ev) or b(ev))(node, parse_and())
        return node

    def parse_and():
        node = parse_not()
        while peek() == "and":
            take()
            node = (lambda a, b: lambda ev: a(ev) and b(ev))(node, parse_not())
        return node

    def parse_not():
        if peek() == "not":
            take()
            inner = parse_not()
            return lambda ev: not inner(ev)
        if peek() == "(":
            take()
            node = parse_or()
            if peek() != ")":
                raise ValueError(f"missing ) in condition {expr!r}")
            take()
            return node
        name = peek()
        if name is None or name not in selections:
            raise ValueError(f"unknown selection {name!r} in condition {expr!r}")
        take()
        return selections[name]

    node = parse_or()
    if pos != len(tokens):
        raise ValueError(f"unexpected {peek()!r} in condition {expr!r}")
    return node


def _seconds(value) -> int:
    if isinstance(value, int):
        return value
    m = re.fullmatch(r"(\d+)([smh])", str(value))
    if not m:
        raise ValueError(f"timespan must look like 60s, 5m or 2h, got {value!r}")
    return int(m[1]) * {"s": 1, "m": 60, "h": 3600}[m[2]]


class Correlation(BaseModel):
    type: Literal["event_count", "value_count", "temporal", "impossible_travel"]
    group_by: list[str]
    timespan: int
    cooldown: int | None = None  # how long a rule stays quiet for the same key after firing; defaults to timespan
    threshold: int = 1
    value_field: str | None = None
    sequence: list[str] | None = None
    max_speed_kmh: float = 900
    min_distance_km: float = 500

    @field_validator("timespan", "cooldown", mode="before")
    @classmethod
    def _span(cls, v):
        return None if v is None else _seconds(v)

    @model_validator(mode="after")
    def _needs(self):
        if self.type == "value_count" and not self.value_field:
            raise ValueError("value_count needs value_field")
        if self.type == "temporal" and (not self.sequence or len(self.sequence) != 2):
            raise ValueError("temporal needs a sequence of exactly two conditions")
        return self


class Rule(BaseModel):
    id: str
    title: str
    description: str
    level: Literal["low", "medium", "high", "critical"]
    tags: list[str]
    detection: dict
    correlation: Correlation
    incident_type: str
    _match: Callable = PrivateAttr()
    _steps: list = PrivateAttr(default_factory=list)

    @property
    def techniques(self) -> list[str]:
        return [t.split(".", 1)[1].upper() for t in self.tags if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t)]

    @property
    def tactics(self) -> list[str]:
        return [t.split(".", 1)[1] for t in self.tags if t.split(".", 1)[-1] in TACTIC_IDS]

    def model_post_init(self, _ctx) -> None:
        if not self.techniques or not self.tactics:
            raise ValueError(f"rule {self.id} must carry a technique tag (attack.t1110.001) and a tactic tag")
        unknown = [t for t in self.techniques if t not in TECHNIQUES]
        if unknown:
            raise ValueError(f"rule {self.id}: add {unknown} to attack.py so the dashboard can name them")
        spec = dict(self.detection)
        condition = spec.pop("condition", None)
        selections = {name: _selection(body) for name, body in spec.items()}
        c = self.correlation
        if c.type == "temporal":
            self._steps = [compile_condition(step, selections) for step in c.sequence]
        elif not condition:
            raise ValueError(f"rule {self.id} needs a detection condition")
        if condition:
            self._match = compile_condition(condition, selections)

    def matches(self, ev: dict) -> bool:
        return self._match(ev)


def load_rules(directory: Path = RULES_DIR) -> list[Rule]:
    rules = [Rule(**yaml.safe_load(p.read_text(encoding="utf-8"))) for p in sorted(directory.glob("*.yml"))]
    ids = [r.id for r in rules]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate rule ids")
    return rules
