from __future__ import annotations

import pytest

from psm.normalize.canonical import CanonicalJSONError, canonical_json, item_hash


def test_sorted_keys():
    assert canonical_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'


def test_no_whitespace():
    out = canonical_json({"a": [1, 2, {"b": 3}]})
    assert out == '{"a":[1,2,{"b":3}]}'


def test_utf8_preserved():
    assert canonical_json({"name": "café"}) == '{"name":"café"}'


def test_floats_rejected():
    with pytest.raises(CanonicalJSONError):
        canonical_json({"x": 1.5})


def test_nested_float_rejected():
    with pytest.raises(CanonicalJSONError):
        canonical_json({"a": {"b": [1, 2.0]}})


def test_non_string_key_rejected():
    with pytest.raises(CanonicalJSONError):
        canonical_json({1: "one"})


def test_item_hash_deterministic():
    a = {"path": "C:\\Foo", "sha256": "abc", "size": 10}
    b = {"size": 10, "path": "C:\\Foo", "sha256": "abc"}
    assert item_hash(a) == item_hash(b)


def test_item_hash_differs_on_content_change():
    assert item_hash({"a": 1}) != item_hash({"a": 2})


def test_none_and_bool_supported():
    assert canonical_json({"x": None, "y": True, "z": False}) == '{"x":null,"y":true,"z":false}'
