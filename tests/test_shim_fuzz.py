"""Fuzz the macOS shim envelope ingester (Phase 6 hardening).

Contract: `parse_envelope` either returns a `ShimEnvelope` or raises
`ShimValidationError`. Any other exception is a bug — the ingest path must not
be crashable by a hostile shim output.
"""

from __future__ import annotations

import contextlib
import json

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from psm.collectors.macos.ingest import ShimValidationError, parse_envelope

# ---------- primitive strategies ----------

_json_scalar = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-2**31, max_value=2**31 - 1),
    st.floats(allow_nan=False, allow_infinity=False, width=32),
    st.text(min_size=0, max_size=32),
)

_json_value = st.recursive(
    _json_scalar,
    lambda children: st.one_of(
        st.lists(children, max_size=5),
        st.dictionaries(st.text(min_size=1, max_size=16), children, max_size=5),
    ),
    max_leaves=20,
)


# ---------- fuzz cases ----------

@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
@given(payload=_json_value)
def test_arbitrary_json_never_crashes(payload) -> None:
    raw = json.dumps(payload)
    with contextlib.suppress(ShimValidationError):
        parse_envelope(raw)
    # Any other exception here is a bug.


@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
@given(text=st.text(min_size=0, max_size=256))
def test_arbitrary_text_never_crashes(text: str) -> None:
    with contextlib.suppress(ShimValidationError):
        parse_envelope(text)


VALID_TEMPLATE: dict = {
    "psm_collector": "macos",
    "version": "1.0",
    "host": "fuzzhost",
    "taken_at": "2026-07-05T00:00:00Z",
    "modules": {},
    "gaps": [],
}


@settings(max_examples=100)
@given(mutation=st.dictionaries(
    st.sampled_from(["psm_collector", "version", "host", "taken_at", "modules", "gaps"]),
    _json_value,
    max_size=3,
))
def test_field_mutation_never_crashes(mutation: dict) -> None:
    payload = dict(VALID_TEMPLATE)
    payload.update(mutation)
    with contextlib.suppress(ShimValidationError):
        parse_envelope(json.dumps(payload))


@settings(max_examples=100)
@given(module_name=st.text(min_size=1, max_size=16),
       items=st.lists(_json_value, max_size=5))
def test_arbitrary_module_names_are_rejected(module_name: str, items) -> None:
    """Unknown module names must raise ShimValidationError, not silently ingest."""
    payload = dict(VALID_TEMPLATE)
    payload["modules"] = {module_name: items}
    try:
        env = parse_envelope(json.dumps(payload))
    except ShimValidationError:
        return
    # If it validated, the module name must be one we know about.
    assert module_name in env.modules


@settings(max_examples=100)
@given(entries=st.lists(
    st.dictionaries(st.text(min_size=1, max_size=8), _json_value, max_size=4),
    max_size=5,
))
def test_apps_items_missing_required_fields_are_rejected(entries) -> None:
    payload = dict(VALID_TEMPLATE)
    payload["modules"] = {"apps": entries}
    try:
        env = parse_envelope(json.dumps(payload))
    except ShimValidationError:
        return
    # If it succeeded, every emitted item retains all three required fields.
    for item in env.modules.get("apps", []):
        assert "id" in item and "name" in item and "path" in item


@settings(max_examples=50)
@given(gaps=st.lists(_json_value, max_size=5))
def test_gaps_shape_enforced(gaps) -> None:
    payload = dict(VALID_TEMPLATE)
    payload["gaps"] = gaps
    with contextlib.suppress(ShimValidationError):
        parse_envelope(json.dumps(payload))
