"""Chrome/Edge Preferences parser tests."""

from __future__ import annotations

from pathlib import Path

from psm.collectors.windows.modules.browser import BrowserConfig, collect

FIXTURES = Path(__file__).parent / "fixtures" / "windows"


def test_chrome_preferences_parses_manifest_fields() -> None:
    entries, gaps = collect(BrowserConfig(
        chrome_user_data=(str(FIXTURES / "chrome_userdata"),),
    ))
    assert gaps == []
    by_id = {e["id"]: e for e in entries}
    ext = by_id["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
    assert ext["browser"] == "chrome"
    assert ext["name"] == "Legit Reader"
    assert ext["version"] == "1.2.3"
    assert ext["permissions"] == ["storage"]
    assert ext["enabled"] is True
    assert ext["install_time"] is not None  # FILETIME → ISO


def test_broad_permission_extension_surfaces_all_urls() -> None:
    entries, _ = collect(BrowserConfig(
        chrome_user_data=(str(FIXTURES / "chrome_userdata_broad"),),
    ))
    by_id = {e["id"]: e for e in entries}
    evil = by_id["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]
    assert "<all_urls>" in evil["permissions"]
    assert "tabs" in evil["permissions"]


def test_missing_user_data_dir_is_not_a_gap() -> None:
    entries, gaps = collect(BrowserConfig(
        chrome_user_data=(str(FIXTURES / "does_not_exist"),),
        edge_user_data=(str(FIXTURES / "does_not_exist"),),
        firefox_profiles_ini=(str(FIXTURES / "does_not_exist"),),
    ))
    assert entries == []
    assert gaps == []


def test_malformed_preferences_becomes_gap(tmp_path: Path) -> None:
    (tmp_path / "Default").mkdir()
    (tmp_path / "Default" / "Preferences").write_text("not-json{", encoding="utf-8")
    entries, gaps = collect(BrowserConfig(chrome_user_data=(str(tmp_path),)))
    assert entries == []
    assert len(gaps) == 1
    assert gaps[0].reason == "preferences-unreadable"
