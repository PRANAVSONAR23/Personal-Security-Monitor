"""YAML-driven correlation rules (LLD §5, implementation §3.9).

Two rule shapes:

- match: a single-event predicate — bumps that event's severity and (for alert-level rules)
  produces an alert with just this event as evidence.
- correlate: pairs two event streams via a restricted `a.payload.X == b.payload.Y` join
  and produces one alert per matched pair.

Predicates supported in `where` blocks:

    payload.field: value                  # scalar eq
    payload.field: [v1, v2]               # membership (in)
    payload.field: { prefix_any: [...] }  # any string prefix, path-normalized for path fields
    payload.field: { exists: true|false } # payload key present

Path predicates and correlate joins go through `norm_path` so casing never breaks them.
Broken user rules are logged and skipped — never fatal.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from psm.core.models import Event, Platform, Severity
from psm.normalize.paths import norm_path

log = logging.getLogger(__name__)

_SEVERITY_ORDER: dict[str, int] = {"info": 0, "notice": 1, "warning": 2, "alert": 3}
_VALID_SEVERITIES = ("info", "notice", "warning", "alert")
_VALID_ACTIONS = ("added", "removed", "changed", "observed")

# ---------- predicate types ----------

_PATH_FIELDS = frozenset({"path", "target", "value", "install_location", "image_path"})


@dataclass(slots=True)
class Predicate:
    """One field predicate. Exactly one of eq/in_/prefix_any/has_any/exists is set."""

    field_path: tuple[str, ...]  # ("payload", "signature_status")
    eq: object | None = None
    in_: tuple[object, ...] | None = None
    prefix_any: tuple[str, ...] | None = None
    has_any: tuple[object, ...] | None = None  # list-valued field ∩ has_any is non-empty
    exists: bool | None = None

    def evaluate(  # noqa: PLR0911 — one early return per predicate op reads better
        self, event: Event, payload: dict[str, Any], platform: Platform
    ) -> bool:
        value = _resolve(self.field_path, event, payload)
        if self.exists is not None:
            return (value is not None) == self.exists
        if value is None:
            return False
        if self.eq is not None:
            return bool(value == self.eq)
        if self.in_ is not None:
            return value in self.in_
        if self.has_any is not None:
            if not isinstance(value, list):
                return False
            wanted = set(self.has_any)
            return any(item in wanted for item in value)
        if self.prefix_any is not None:
            if not isinstance(value, str):
                return False
            candidate = _maybe_norm(self.field_path, value, platform)
            return any(
                candidate.startswith(_maybe_norm(self.field_path, p, platform))
                for p in self.prefix_any
            )
        return True


def _resolve(field_path: tuple[str, ...], event: Event, payload: dict[str, Any]) -> Any:
    if field_path[0] == "payload":
        cur: Any = payload
        for part in field_path[1:]:
            if not isinstance(cur, dict) or part not in cur:
                return None
            cur = cur[part]
        return cur
    # top-level event fields
    return getattr(event, field_path[0], None)


def _maybe_norm(field_path: tuple[str, ...], value: str, platform: Platform) -> str:
    """Path-shaped fields compare through the *device's* normalization.

    v1 hardcoded "windows" here, which casefolded macOS and Android paths and
    silently merged `/Users/Pranav/x` with `/users/pranav/x` in every prefix
    predicate and correlate join.
    """
    if field_path[0] == "payload" and len(field_path) > 1 and field_path[-1] in _PATH_FIELDS:
        return norm_path(value, platform)
    return value


# ---------- rule shapes ----------


@dataclass(slots=True)
class MatchClause:
    category: str | None
    action: str | None
    where: tuple[Predicate, ...] = field(default_factory=tuple)

    def matches(self, event: Event, payload: dict[str, Any], platform: Platform) -> bool:
        if self.category is not None and event.category != self.category:
            return False
        if self.action is not None and event.action != self.action:
            return False
        return all(p.evaluate(event, payload, platform) for p in self.where)


@dataclass(slots=True)
class CorrelateJoin:
    left_field: tuple[str, ...]  # ("payload", "target")
    right_field: tuple[str, ...]  # ("payload", "path")


@dataclass(slots=True)
class CorrelateClause:
    a: MatchClause
    b: MatchClause
    join: CorrelateJoin


@dataclass(slots=True)
class Rule:
    id: str
    severity: Severity
    title: str
    match: MatchClause | None = None
    correlate: CorrelateClause | None = None


# ---------- loader ----------


class RuleParseError(ValueError):
    pass


def _parse_predicate(field_path: tuple[str, ...], raw: Any) -> Predicate:  # noqa: PLR0911
    if isinstance(raw, dict):
        if len(raw) != 1:
            raise RuleParseError(f"{'.'.join(field_path)}: predicate dict must have one key")
        ((op, arg),) = raw.items()
        if op == "prefix_any":
            if not isinstance(arg, list) or not all(isinstance(x, str) for x in arg):
                raise RuleParseError(f"{'.'.join(field_path)}: prefix_any expects list[str]")
            return Predicate(field_path=field_path, prefix_any=tuple(arg))
        if op == "exists":
            if not isinstance(arg, bool):
                raise RuleParseError(f"{'.'.join(field_path)}: exists expects bool")
            return Predicate(field_path=field_path, exists=arg)
        if op == "eq":
            return Predicate(field_path=field_path, eq=arg)
        if op == "in":
            if not isinstance(arg, list):
                raise RuleParseError(f"{'.'.join(field_path)}: in expects list")
            return Predicate(field_path=field_path, in_=tuple(arg))
        if op == "has_any":
            if not isinstance(arg, list):
                raise RuleParseError(f"{'.'.join(field_path)}: has_any expects list")
            return Predicate(field_path=field_path, has_any=tuple(arg))
        raise RuleParseError(f"{'.'.join(field_path)}: unknown predicate op {op!r}")

    if isinstance(raw, list):
        return Predicate(field_path=field_path, in_=tuple(raw))

    return Predicate(field_path=field_path, eq=raw)


def _parse_where(raw: dict[str, Any] | None) -> tuple[Predicate, ...]:
    if not raw:
        return ()
    preds: list[Predicate] = []
    for key, value in raw.items():
        path = tuple(key.split("."))
        preds.append(_parse_predicate(path, value))
    return tuple(preds)


def _parse_match(raw: dict[str, Any]) -> MatchClause:
    category = raw.get("category")
    action = raw.get("action")
    if action is not None and action not in _VALID_ACTIONS:
        raise RuleParseError(f"unknown action {action!r}")
    return MatchClause(
        category=category if category is None else str(category),
        action=action if action is None else str(action),
        where=_parse_where(raw.get("where")),
    )


def _parse_join(raw: str) -> CorrelateJoin:
    if "==" not in raw:
        raise RuleParseError(f"join must use '==': got {raw!r}")
    left, right = (s.strip() for s in raw.split("==", 1))
    if not left.startswith("a.") or not right.startswith("b."):
        raise RuleParseError(f"join must be 'a.<field> == b.<field>': got {raw!r}")
    return CorrelateJoin(
        left_field=tuple(left[2:].split(".")),
        right_field=tuple(right[2:].split(".")),
    )


def _parse_correlate(raw: dict[str, Any]) -> CorrelateClause:
    if "a" not in raw or "b" not in raw or "join" not in raw:
        raise RuleParseError("correlate requires a, b, and join")
    return CorrelateClause(
        a=_parse_match(raw["a"]),
        b=_parse_match(raw["b"]),
        join=_parse_join(str(raw["join"])),
    )


def _parse_rule(raw: dict[str, Any]) -> Rule:
    if "id" not in raw or "severity" not in raw or "title" not in raw:
        raise RuleParseError("rule requires id, severity, and title")
    sev = str(raw["severity"])
    if sev not in _VALID_SEVERITIES:
        raise RuleParseError(f"unknown severity {sev!r}")
    match = _parse_match(raw["match"]) if "match" in raw else None
    correlate = _parse_correlate(raw["correlate"]) if "correlate" in raw else None
    if match is None and correlate is None:
        raise RuleParseError("rule needs either match or correlate")
    if match is not None and correlate is not None:
        raise RuleParseError("rule cannot have both match and correlate")
    return Rule(
        id=str(raw["id"]),
        severity=sev,  # type: ignore[arg-type]
        title=str(raw["title"]),
        match=match,
        correlate=correlate,
    )


def load_rules_from_dir(directory: Path) -> list[Rule]:
    rules: list[Rule] = []
    if not directory.exists():
        return rules
    for path in sorted(directory.glob("*.yaml")):
        try:
            docs = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as e:
            log.warning("skipping %s: %s", path, e)
            continue
        raw_rules = docs if isinstance(docs, list) else [docs]
        for entry in raw_rules:
            if not isinstance(entry, dict):
                log.warning("skipping non-mapping rule in %s", path)
                continue
            try:
                rules.append(_parse_rule(entry))
            except RuleParseError as e:
                log.warning("skipping rule in %s: %s", path, e)
    return rules


BUILTIN_DIR = Path(__file__).resolve().parent.parent / "rules" / "builtin"


def load_builtin_rules() -> list[Rule]:
    return load_rules_from_dir(BUILTIN_DIR)


# ---------- evaluator ----------

PayloadResolver = Callable[[Event], dict[str, Any]]


@dataclass(slots=True)
class AlertIntent:
    rule_id: str
    title: str
    severity: Severity
    contributing_events: tuple[Event, ...]
    context: dict[str, Any]


def _bump_severity(event: Event, new_sev: Severity) -> None:
    if _SEVERITY_ORDER[new_sev] > _SEVERITY_ORDER[event.severity]:
        event.severity = new_sev


def _extract_join_value(
    field_path: tuple[str, ...], event: Event, payload: dict[str, Any], platform: Platform
) -> str | None:
    value = _resolve(field_path, event, payload)
    if not isinstance(value, str):
        return None
    return _maybe_norm(field_path, value, platform)


def evaluate(  # noqa: PLR0912
    rules: Iterable[Rule],
    events: Iterable[Event],
    resolve_payload: PayloadResolver,
    platform: Platform = "macos",
) -> list[AlertIntent]:
    """Mutate event.severity in place; return alert intents.

    An alert is produced for every rule whose severity == "alert" that fires.
    Non-alert rules bump event severity but do not create alerts.
    """
    events_list = list(events)
    payloads = {id(e): resolve_payload(e) for e in events_list}
    alerts: list[AlertIntent] = []

    for rule in rules:
        if rule.match is not None:
            for e in events_list:
                if rule.match.matches(e, payloads[id(e)], platform):
                    _bump_severity(e, rule.severity)
                    if rule.severity == "alert":
                        alerts.append(
                            AlertIntent(
                                rule_id=rule.id,
                                title=rule.title,
                                severity=rule.severity,
                                contributing_events=(e,),
                                context={"event_id": None, "subject_key": e.subject_key},
                            )
                        )
        elif rule.correlate is not None:
            c = rule.correlate
            a_hits = [
                (e, _extract_join_value(c.join.left_field, e, payloads[id(e)], platform))
                for e in events_list
                if c.a.matches(e, payloads[id(e)], platform)
            ]
            b_by_value: dict[str, list[Event]] = {}
            for e in events_list:
                if not c.b.matches(e, payloads[id(e)], platform):
                    continue
                val = _extract_join_value(c.join.right_field, e, payloads[id(e)], platform)
                if val is None:
                    continue
                b_by_value.setdefault(val, []).append(e)
            for a_event, a_val in a_hits:
                if a_val is None:
                    continue
                for b_event in b_by_value.get(a_val, []):
                    _bump_severity(a_event, rule.severity)
                    _bump_severity(b_event, rule.severity)
                    if rule.severity == "alert":
                        alerts.append(
                            AlertIntent(
                                rule_id=rule.id,
                                title=rule.title,
                                severity=rule.severity,
                                contributing_events=(a_event, b_event),
                                context={
                                    "a_subject": a_event.subject_key,
                                    "b_subject": b_event.subject_key,
                                    "join_value": a_val,
                                },
                            )
                        )
    return alerts
