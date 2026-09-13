"""Ingest tests: schema-validation, unknown-module rejection, unknown-field drop."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from psm.collectors.macos.ingest import (
    ShimValidationError,
    envelope_to_bundle,
    parse_envelope,
    parse_file,
)
from psm.core.models import Device
from psm.normalize.macos import MacosNormalizer

FIXTURES = Path(__file__).parent / "fixtures" / "macos"


def test_baseline_fixture_parses() -> None:
    env = parse_envelope((FIXTURES / "baseline.json").read_bytes())
    assert env.host == "macbook.local"
    assert env.version == "1.0"
    assert set(env.modules) == {"apps", "persistence", "permissions"}
    assert env.modules["apps"][0]["id"] == "com.apple.Safari"


def test_unknown_module_rejected() -> None:
    payload = json.loads((FIXTURES / "baseline.json").read_text())
    payload["modules"]["bogus"] = []
    with pytest.raises(ShimValidationError, match="unknown module"):
        parse_envelope(json.dumps(payload))


def test_unknown_field_dropped() -> None:
    payload = json.loads((FIXTURES / "baseline.json").read_text())
    payload["modules"]["apps"][0]["hostile_key"] = "should be dropped"
    env = parse_envelope(json.dumps(payload))
    assert "hostile_key" not in env.modules["apps"][0]
    # Required fields still present:
    assert env.modules["apps"][0]["id"] == "com.apple.Safari"


def test_missing_required_field_rejected() -> None:
    payload = json.loads((FIXTURES / "baseline.json").read_text())
    del payload["modules"]["apps"][0]["path"]
    with pytest.raises(ShimValidationError, match="required field"):
        parse_envelope(json.dumps(payload))


def test_bad_version_rejected() -> None:
    payload = json.loads((FIXTURES / "baseline.json").read_text())
    payload["version"] = "9.9"
    with pytest.raises(ShimValidationError, match="unsupported shim version"):
        parse_envelope(json.dumps(payload))


def test_wrong_collector_rejected() -> None:
    payload = json.loads((FIXTURES / "baseline.json").read_text())
    payload["psm_collector"] = "windows"
    with pytest.raises(ShimValidationError, match="unexpected psm_collector"):
        parse_envelope(json.dumps(payload))


def test_normalizer_subject_keys() -> None:
    device = Device(name="mac", platform="macos", identifier="user@macbook.local")
    bundle = parse_file(device, str(FIXTURES / "baseline.json"))
    items = MacosNormalizer().normalize(bundle)
    subjects = {(i.category, i.subject_key) for i in items}
    assert ("application", "pkg:com.apple.Safari") in subjects
    assert (
        "persistence",
        "persist:macos:launchagent:com.apple.Spotlight",
    ) in subjects
    assert ("permission", "perm:com.apple.Safari:kTCCServiceCamera") in subjects


def test_envelope_to_bundle_maps_module_names_to_categories() -> None:
    device = Device(name="mac", platform="macos", identifier="user@macbook.local")
    env = parse_envelope((FIXTURES / "baseline.json").read_bytes())
    bundle = envelope_to_bundle(device, env)
    # Shim's `apps` → inventory category `application`, etc.
    assert set(bundle.raw) == {"application", "persistence", "permission"}
