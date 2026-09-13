from __future__ import annotations

from psm.normalize.paths import norm_path


def test_windows_slashes_and_case():
    assert norm_path("C:/Users/X/Foo.EXE", "windows") == "c:\\users\\x\\foo.exe"


def test_windows_drive_letter_normalized():
    assert norm_path("d:\\bar", "windows") == norm_path("D:\\BAR", "windows")


def test_windows_no_drive_letter():
    assert norm_path("relative\\path\\File", "windows") == "relative\\path\\file"


def test_macos_pass_through():
    assert norm_path("/Users/x/Bar.txt", "macos") == "/Users/x/Bar.txt"


def test_android_pass_through():
    assert norm_path("/sdcard/Download/x", "android") == "/sdcard/Download/x"
