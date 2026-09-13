from __future__ import annotations

from psm.core.models import Event
from psm.core.rules import (
    CorrelateClause,
    CorrelateJoin,
    MatchClause,
    Predicate,
    Rule,
    evaluate,
    load_builtin_rules,
)


def _event(**kwargs) -> Event:
    defaults = dict(
        device_id=1,
        ts="2026-07-05T12:00:00Z",
        category="file",
        action="added",
        subject_key="file:x",
        snap_to=1,
    )
    defaults.update(kwargs)
    return Event(**defaults)


# ---------- predicates ----------


def test_predicate_eq_scalar():
    p = Predicate(field_path=("payload", "signature_status"), eq="unsigned")
    ev = _event()
    assert p.evaluate(ev, {"signature_status": "unsigned"}, "macos") is True
    assert p.evaluate(ev, {"signature_status": "valid"}, "macos") is False


def test_predicate_in_list():
    p = Predicate(field_path=("payload", "signature_status"), in_=("unsigned", "invalid"))
    ev = _event()
    assert p.evaluate(ev, {"signature_status": "invalid"}, "macos") is True
    assert p.evaluate(ev, {"signature_status": "notarized"}, "macos") is False


def test_predicate_prefix_any_path_normalized_macos():
    """APFS is case-insensitive, so a prefix must match regardless of casing."""
    p = Predicate(field_path=("payload", "path"), prefix_any=("/Users/",))
    ev = _event()
    assert p.evaluate(ev, {"path": "/USERS/x/foo"}, "macos") is True
    assert p.evaluate(ev, {"path": "/opt/homebrew/bin/foo"}, "macos") is False


def test_predicate_prefix_any_not_folded_on_android():
    """F6: Android is case-sensitive; folding there would match the wrong file."""
    p = Predicate(field_path=("payload", "path"), prefix_any=("/sdcard/Download/",))
    ev = _event()
    assert p.evaluate(ev, {"path": "/sdcard/Download/a.apk"}, "android") is True
    assert p.evaluate(ev, {"path": "/sdcard/download/a.apk"}, "android") is False


def test_predicate_prefix_any_windows_branch_retained():
    """norm_path keeps a Windows branch for a future Windows target."""
    p = Predicate(field_path=("payload", "path"), prefix_any=("C:\\Users\\",))
    ev = _event()
    assert p.evaluate(ev, {"path": "C:/USERS/x/foo.exe"}, "windows") is True
    assert p.evaluate(ev, {"path": "D:\\Tools\\foo.exe"}, "windows") is False


def test_predicate_has_any_list_intersection():
    p = Predicate(
        field_path=("payload", "permissions"),
        has_any=("<all_urls>", "*://*/*"),
    )
    ev = _event(category="browser")
    assert p.evaluate(ev, {"permissions": ["storage", "<all_urls>"]}, "macos") is True
    assert p.evaluate(ev, {"permissions": ["storage", "tabs"]}, "macos") is False
    # Non-list value → False, not an exception.
    assert p.evaluate(ev, {"permissions": "<all_urls>"}, "macos") is False


def test_predicate_exists():
    p_true = Predicate(field_path=("payload", "sha256"), exists=True)
    p_false = Predicate(field_path=("payload", "sha256"), exists=False)
    ev = _event()
    assert p_true.evaluate(ev, {"sha256": "abc"}, "macos") is True
    assert p_true.evaluate(ev, {}, "macos") is False
    assert p_false.evaluate(ev, {}, "macos") is True


def test_predicate_missing_payload_field_is_false():
    p = Predicate(field_path=("payload", "signature_status"), eq="unsigned")
    assert p.evaluate(_event(), {}, "macos") is False


# ---------- match rules ----------


def test_match_bumps_severity_and_produces_alert():
    rule = Rule(
        id="test",
        severity="alert",
        title="unsigned",
        match=MatchClause(
            category="file",
            action="added",
            where=(Predicate(field_path=("payload", "signature_status"), in_=("unsigned",)),),
        ),
    )
    ev = _event()
    alerts = evaluate([rule], [ev], lambda _: {"signature_status": "unsigned"})
    assert ev.severity == "alert"
    assert len(alerts) == 1
    assert alerts[0].rule_id == "test"


def test_match_never_downgrades_severity():
    rule = Rule(
        id="notice-rule",
        severity="notice",
        title="new app",
        match=MatchClause(category="application", action="added"),
    )
    ev = _event(category="application", severity="alert")
    evaluate([rule], [ev], lambda _: {})
    assert ev.severity == "alert"  # remains at the higher level


# ---------- correlate ----------


def test_correlate_pairs_events_by_path():
    rule = Rule(
        id="persist-plus-file",
        severity="alert",
        title="persistence + file",
        correlate=CorrelateClause(
            a=MatchClause(category="persistence", action="added"),
            b=MatchClause(category="file", action="added"),
            join=CorrelateJoin(
                left_field=("payload", "target"),
                right_field=("payload", "path"),
            ),
        ),
    )
    persist_ev = _event(category="persistence", subject_key="persist:macos:launchagent:com.bar")
    file_ev = _event(subject_key="file:/Users/x/Library/bar")

    def resolver(e: Event) -> dict:
        if e is persist_ev:
            return {"target": "/Users/X/Library/BAR"}  # different casing on purpose
        return {"path": "/users/x/library/bar"}

    # APFS is case-insensitive, so the join must still pair these two.
    alerts = evaluate([rule], [persist_ev, file_ev], resolver, "macos")
    assert len(alerts) == 1
    assert persist_ev.severity == "alert"
    assert file_ev.severity == "alert"
    assert alerts[0].contributing_events == (persist_ev, file_ev)


def test_correlate_no_pair_no_alert():
    rule = Rule(
        id="persist-plus-file",
        severity="alert",
        title="persistence + file",
        correlate=CorrelateClause(
            a=MatchClause(category="persistence", action="added"),
            b=MatchClause(category="file", action="added"),
            join=CorrelateJoin(
                left_field=("payload", "target"),
                right_field=("payload", "path"),
            ),
        ),
    )
    persist_ev = _event(category="persistence")
    file_ev = _event()

    def resolver(e: Event) -> dict:
        if e is persist_ev:
            return {"target": "C:\\Foo\\A.exe"}
        return {"path": "C:\\Bar\\B.exe"}

    alerts = evaluate([rule], [persist_ev, file_ev], resolver)
    assert alerts == []
    assert persist_ev.severity == "info"
    assert file_ev.severity == "info"


# ---------- built-ins ----------


def test_builtin_rules_load():
    rules = load_builtin_rules()
    ids = {r.id for r in rules}
    assert {
        "unsigned-binary-user-path",
        "persistence-plus-new-file",
        "new-hklm-persistence",
        "new-hkcu-persistence",
        "new-application",
        "new-browser-extension-all-urls",
    } <= ids
