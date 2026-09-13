"""macOS collection modules, driven by fixtures rather than this machine's state.

The golden inputs are shaped from real data read off the development Mac —
including the malformed system plist and the Secure Preferences layout that
broke v1.
"""

from __future__ import annotations

import json
import plistlib
import sqlite3
from pathlib import Path

from psm.collectors.base import RawBundle
from psm.collectors.macos.modules import browser, files, launchd, tcc
from psm.core.models import Device
from psm.normalize.macos import MacosNormalizer

# The exact byte pattern of /System/Library/LaunchAgents/com.apple.familycircled.plist,
# which raises xml.parsers.expat.ExpatError — not OSError, not InvalidFileException.
MALFORMED_PLIST = b"<?xml version='1.0' encoding='UTF-8'\n<plist></plist>"


def _write_plist(path: Path, label: str, program: str, **extra) -> None:
    body = {"Label": label, "ProgramArguments": [program], "RunAtLoad": True, **extra}
    with path.open("wb") as f:
        plistlib.dump(body, f)


# ---------- launchd ----------


def test_launchd_reads_jobs_and_survives_a_malformed_sibling(tmp_path, monkeypatch):
    """F2 in the module that actually lost 471 entries in v1."""
    agents = tmp_path / "Library" / "LaunchAgents"
    agents.mkdir(parents=True)
    for i in range(3):
        _write_plist(agents / f"com.example.{i}.plist", f"com.example.{i}", f"/usr/bin/tool{i}")
    (agents / "broken.plist").write_bytes(MALFORMED_PLIST)

    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(launchd, "LAUNCH_DIRS", ())
    result = launchd.collect(include_system=False, with_login_items=False)

    assert result.ok is True
    assert len(result.entries) == 3
    assert len(result.gaps) == 1
    assert "ExpatError" in result.gaps[0].detail


def test_launchd_extracts_target_and_args(tmp_path, monkeypatch):
    agents = tmp_path / "Library" / "LaunchAgents"
    agents.mkdir(parents=True)
    with (agents / "j.plist").open("wb") as f:
        plistlib.dump(
            {
                "Label": "com.example.j",
                "ProgramArguments": ["/usr/local/bin/agent", "--daemon", "-v"],
                "RunAtLoad": True,
                "KeepAlive": True,
            },
            f,
        )
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(launchd, "LAUNCH_DIRS", ())
    entry = launchd.collect(include_system=False, with_login_items=False).entries[0]

    assert entry["target"] == "/usr/local/bin/agent"
    assert entry["args"] == ["--daemon", "-v"]
    assert entry["run_at_load"] is True
    assert entry["keep_alive"] is True
    assert entry["scope"] == "user"


def test_launchd_no_readable_dirs_is_a_failure_not_an_empty_result(tmp_path, monkeypatch):
    """F1: 'could not look' must not present as 'nothing there'."""
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(launchd, "LAUNCH_DIRS", ())
    result = launchd.collect(include_system=False, with_login_items=False)
    assert result.ok is False


BTM_SAMPLE = """\
========================
 Records for UID 501 : ABCD-EF01
========================

 Items:

 #1:
                 UUID: E9924669-05C9-4CEF-A47F-941F7DE6E707
                 Name: Docker
       Developer Name: Docker
                 Type: developer (0x20)
          Disposition: [disabled, allowed, not notified] (0x2)
           Identifier: Docker
                  URL: (null)
  Embedded Item Identifiers:
    #1: 16.com.docker.vmnetd

 #2:
                 UUID: 001D4DC9-8C4E-40A8-9500-99013DECAAB1
                 Name: com.docker.vmnetd
       Developer Name: Docker
      Team Identifier: 9BNSXJN65R
                 Type: legacy daemon (0x10010)
          Disposition: [enabled, allowed, notified] (0xb)
           Identifier: 16.com.docker.vmnetd
                  URL: file:///Library/LaunchDaemons/com.docker.vmnetd.plist
      Executable Path: /Library/PrivilegedHelperTools/com.docker.vmnetd
    Assoc. Bundle IDs: [ com.docker.docker ]
"""


def test_btm_parser_ignores_nested_lists():
    """`Embedded Item Identifiers` reuses `#n:` numbering; a naive splitter
    turns each nested line into a phantom record."""
    entries = launchd._parse_btm(BTM_SAMPLE)
    assert len(entries) == 2
    assert [e["name"] for e in entries] == ["Docker", "com.docker.vmnetd"]


def test_btm_parser_maps_null_and_disposition():
    entries = launchd._parse_btm(BTM_SAMPLE)
    docker, vmnetd = entries
    assert docker["path"] == ""  # URL was the literal "(null)"
    assert docker["enabled"] is False  # disposition says disabled
    assert vmnetd["enabled"] is True
    assert vmnetd["team_id"] == "9BNSXJN65R"
    assert vmnetd["target"] == "/Library/PrivilegedHelperTools/com.docker.vmnetd"
    assert docker["uid"] == "501"


# ---------- tcc ----------


def _only_user_tcc(monkeypatch, tmp_path: Path) -> None:
    """Isolate from the real system TCC.db, which is readable once FDA is granted."""
    user = tmp_path / "Library" / "Application Support" / "com.apple.TCC" / "TCC.db"
    monkeypatch.setattr(tcc, "_sources", lambda: [(user, "user")])


def _make_tcc(path: Path, rows: list[tuple]) -> None:
    conn = sqlite3.connect(str(path))
    conn.execute(
        "CREATE TABLE access (service TEXT, client TEXT, client_type INTEGER, "
        "auth_value INTEGER, auth_reason INTEGER, indirect_object_identifier TEXT, "
        "PRIMARY KEY (service, client, client_type, indirect_object_identifier))"
    )
    conn.executemany("INSERT INTO access VALUES (?,?,?,?,?,?)", rows)
    conn.commit()
    conn.close()


def test_tcc_auth_value_is_not_coerced_to_bool(tmp_path, monkeypatch):
    """v1 used bool(auth_value): 5 (limited) became a full grant."""
    tcc_dir = tmp_path / "Library" / "Application Support" / "com.apple.TCC"
    tcc_dir.mkdir(parents=True)
    _make_tcc(
        tcc_dir / "TCC.db",
        [
            ("kTCCServiceCamera", "com.a", 0, 2, 2, "UNUSED"),
            ("kTCCServiceCamera", "com.b", 0, 0, 2, "UNUSED"),
            ("kTCCServiceSystemPolicyAppData", "com.c", 0, 5, 2, "UNUSED"),
            ("kTCCServiceCamera", "com.d", 0, 99, 2, "UNUSED"),
        ],
    )
    _only_user_tcc(monkeypatch, tmp_path)
    by_pkg = {e["pkg"]: e for e in tcc.collect().entries}

    assert (by_pkg["com.a"]["state"], by_pkg["com.a"]["granted"]) == ("allowed", True)
    assert (by_pkg["com.b"]["state"], by_pkg["com.b"]["granted"]) == ("denied", False)
    assert (by_pkg["com.c"]["state"], by_pkg["com.c"]["granted"]) == ("limited", False)
    # An unrecognised value is reported as unknown, never silently granted.
    assert (by_pkg["com.d"]["state"], by_pkg["com.d"]["granted"]) == ("unknown", False)


def test_tcc_indirect_object_keeps_grants_distinct(tmp_path, monkeypatch):
    """TCC's primary key includes indirect_object_identifier; dropping it
    collapses 'may drive Brave' and 'may drive Chrome' into one item."""
    tcc_dir = tmp_path / "Library" / "Application Support" / "com.apple.TCC"
    tcc_dir.mkdir(parents=True)
    _make_tcc(
        tcc_dir / "TCC.db",
        [
            ("kTCCServiceAppleEvents", "com.t", 0, 0, 3, "com.brave.Browser"),
            ("kTCCServiceAppleEvents", "com.t", 0, 0, 4, "com.google.Chrome"),
        ],
    )
    _only_user_tcc(monkeypatch, tmp_path)
    entries = tcc.collect().entries

    bundle = RawBundle(device=Device(name="m", platform="macos", identifier="local"))
    bundle.record("permission", entries)
    keys = {i.subject_key for i in MacosNormalizer().normalize(bundle)}
    assert len(keys) == 2, keys


def test_tcc_missing_database_is_a_gap_not_an_empty_grant_list(tmp_path, monkeypatch):
    _only_user_tcc(monkeypatch, tmp_path)
    result = tcc.collect()
    assert result.ok is False
    assert any(g.reason in ("tcc-missing", "fda-missing") for g in result.gaps)


# ---------- browser ----------


def _chromium_profile(root: Path, filename: str, extensions: dict) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / filename).write_text(
        json.dumps({"extensions": {"settings": extensions}}), encoding="utf-8"
    )


BROAD_EXT = {
    "aaaabbbbccccddddeeeeffffgggghhhh": {
        "state": 1,
        "from_webstore": True,
        "manifest": {
            "name": "Broad Ext",
            "version": "1.2",
            "manifest_version": 3,
            "permissions": ["tabs", "storage"],
            "host_permissions": ["<all_urls>"],
        },
    }
}


def test_browser_reads_secure_preferences(tmp_path, monkeypatch):
    """F3: modern Chromium keeps extensions.settings in Secure Preferences.
    v1 read only Preferences and reported 0 of 21 real extensions, with no gap."""
    prof = tmp_path / "Library" / "Application Support" / "Google" / "Chrome" / "Default"
    _chromium_profile(prof, "Secure Preferences", BROAD_EXT)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))

    result = browser.collect()
    assert len(result.entries) == 1
    e = result.entries[0]
    assert e["browser"] == "chrome"
    assert e["name"] == "Broad Ext"
    assert e["broad_host_access"] is True
    assert e["permissions"] == ["storage", "tabs"]
    assert e["host_permissions"] == ["<all_urls>"]


def test_browser_still_reads_legacy_preferences(tmp_path, monkeypatch):
    prof = tmp_path / "Library" / "Application Support" / "Google" / "Chrome" / "Default"
    _chromium_profile(prof, "Preferences", BROAD_EXT)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    assert len(browser.collect().entries) == 1


def test_browser_unreadable_store_records_a_gap(tmp_path, monkeypatch):
    """A profile we could not parse must never read as 'no extensions'."""
    prof = tmp_path / "Library" / "Application Support" / "Google" / "Chrome" / "Default"
    prof.mkdir(parents=True)
    (prof / "Secure Preferences").write_text("{not json", encoding="utf-8")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))

    result = browser.collect()
    assert result.entries == []
    assert any(g.reason == "extension-store-unreadable" for g in result.gaps)


def test_browser_covers_brave(tmp_path, monkeypatch):
    prof = (
        tmp_path / "Library" / "Application Support" / "BraveSoftware" / "Brave-Browser" / "Default"
    )
    _chromium_profile(prof, "Secure Preferences", BROAD_EXT)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    assert browser.collect().entries[0]["browser"] == "brave"


def test_browser_themes_are_not_extensions(tmp_path, monkeypatch):
    prof = tmp_path / "Library" / "Application Support" / "Google" / "Chrome" / "Default"
    _chromium_profile(
        prof, "Secure Preferences", {"themeid": {"manifest": {"name": "T", "theme": {}}}}
    )
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    assert browser.collect().entries == []


# ---------- files ----------


def test_file_walk_hashes_and_flags_executables(tmp_path):
    (tmp_path / "plain.txt").write_text("hello")
    script = tmp_path / "run.sh"
    script.write_text("#!/bin/sh\necho hi\n")
    script.chmod(0o755)

    result = files.collect([tmp_path], check_signatures=False)
    by_name = {Path(e["path"]).name: e for e in result.entries}

    assert by_name["plain.txt"]["executable"] is False
    assert by_name["plain.txt"]["signature_status"] == "not-applicable"
    assert by_name["run.sh"]["executable"] is True
    assert len(by_name["plain.txt"]["sha256"]) == 64


def test_extensionless_file_is_not_executable_by_extension_alone(tmp_path):
    """v1's shim listed "" in its executable-extension set, so every
    extensionless file counted as executable."""
    p = tmp_path / "README"
    p.write_text("no extension, not executable")
    p.chmod(0o644)
    entry = files.collect([tmp_path], check_signatures=False).entries[0]
    assert entry["executable"] is False


def test_file_walk_skip_cache_avoids_rehashing(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"payload")
    first = files.collect([tmp_path], check_signatures=False)

    # Poison the cached digest: a cache hit must return it unchanged.
    key = next(iter(first.cache))
    size, mtime, inode, _ = first.cache[key]
    poisoned = {key: (size, mtime, inode, "cached" + "0" * 58)}

    second = files.collect([tmp_path], prior_cache=poisoned, check_signatures=False)
    assert second.entries[0]["sha256"].startswith("cached")


def test_file_walk_oversize_is_recorded_not_dropped(tmp_path):
    (tmp_path / "big.bin").write_bytes(b"x" * 2048)
    entry = files.collect([tmp_path], max_file_mb=0, check_signatures=False).entries[0]
    assert entry["sha256"] is None
    assert entry["skipped"] == "size"


def test_missing_walk_root_is_a_gap(tmp_path):
    result = files.collect([tmp_path / "nope"], check_signatures=False)
    assert result.ok is False
    assert result.gaps[0].reason == "path-missing"
