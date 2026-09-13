from __future__ import annotations

import unicodedata

from psm.normalize.paths import norm_path


def test_windows_folds_case_and_separators():
    assert norm_path("c:/Users/X/A.EXE", "windows") == r"c:\users\x\a.exe"
    assert norm_path(r"C:\Users\X\a.exe", "windows") == norm_path("c:/users/x/A.EXE", "windows")


def test_macos_folds_case_apfs_is_case_insensitive():
    assert norm_path("/Users/Pranav/Foo.app", "macos") == "/users/pranav/foo.app"


def test_android_does_not_fold_case_filesystem_is_case_sensitive():
    """F6 regression: v1 folded every path as Windows, merging distinct Android files."""
    assert norm_path("/sdcard/Foo", "android") != norm_path("/sdcard/foo", "android")


def test_macos_normalizes_unicode_form():
    """macOS APIs return a mix of NFC and NFD; unnormalized compare = phantom diffs."""
    nfd = unicodedata.normalize("NFD", "/Users/x/Café.app")
    nfc = unicodedata.normalize("NFC", "/Users/x/Café.app")
    assert nfd != nfc
    assert norm_path(nfd, "macos") == norm_path(nfc, "macos")


def test_android_normalizes_unicode_form_without_folding():
    nfd = unicodedata.normalize("NFD", "/sdcard/Café")
    nfc = unicodedata.normalize("NFC", "/sdcard/Café")
    assert norm_path(nfd, "android") == norm_path(nfc, "android")
    assert norm_path(nfd, "android") == nfc


def test_windows_path_untouched_on_posix_platforms():
    """A POSIX path must never gain backslashes or a drive letter."""
    assert norm_path("/usr/local/bin/x", "macos") == "/usr/local/bin/x"
    assert "\\" not in norm_path("/usr/local/bin/x", "android")
