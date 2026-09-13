from __future__ import annotations

from psm.collectors.base import RawBundle
from psm.core.models import Device
from psm.normalize.windows import WindowsNormalizer


def _device() -> Device:
    return Device(id=1, name="pc", platform="windows", identifier="localhost")


def test_normalize_persistence_subject_key():
    bundle = RawBundle(device=_device())
    bundle.raw["persistence"] = [
        {
            "location": "runkey",
            "hive": "HKCU",
            "key": r"Software\Microsoft\Windows\CurrentVersion\Run",
            "name": "Foo",
            "value": "C:\\Tools\\Foo.exe -d",
            "target": "C:\\Tools\\Foo.exe",
            "args": ["-d"],
            "enabled": True,
        }
    ]
    items = WindowsNormalizer().normalize(bundle)
    assert len(items) == 1
    item = items[0]
    assert item.category == "persistence"
    # subject key is norm_path'd so casing collisions are impossible
    assert item.subject_key == (
        r"persist:windows:runkey:hkcu\software\microsoft\windows\currentversion\run\foo"
    )
    assert item.payload["target"] == "C:\\Tools\\Foo.exe"  # display keeps original casing


def test_normalize_file_subject_key_casefolded():
    bundle = RawBundle(device=_device())
    bundle.raw["file"] = [
        {"path": "C:\\Users\\X\\Downloads\\Bar.EXE", "sha256": "abc", "size": 10,
         "mtime": "2026-07-05T00:00:00Z"},
    ]
    items = WindowsNormalizer().normalize(bundle)
    assert items[0].subject_key == "file:c:\\users\\x\\downloads\\bar.exe"
    assert items[0].payload["path"] == "C:\\Users\\X\\Downloads\\Bar.EXE"


def test_normalize_app_subject_key_uses_registry_id():
    bundle = RawBundle(device=_device())
    bundle.raw["application"] = [
        {"id": "{DEADBEEF-1234}", "hive": "HKLM", "name": "Foo", "version": "1.0",
         "publisher": "Foo Corp", "path": "C:\\Program Files\\Foo", "installed_at": "2026-07-05",
         "source": "msi"}
    ]
    items = WindowsNormalizer().normalize(bundle)
    assert items[0].subject_key == "pkg:{DEADBEEF-1234}"
    assert items[0].category == "application"


def test_normalize_empty_bundle_produces_nothing():
    bundle = RawBundle(device=_device())
    assert WindowsNormalizer().normalize(bundle) == []
