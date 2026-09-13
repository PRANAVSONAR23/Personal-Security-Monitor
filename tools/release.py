"""Build the psm release bundle.

Usage:
    python tools/release.py [--out dist]

Steps:
    1. `python -m build --wheel --outdir <out>`   (needs `build` in dev deps)
    2. Copy `shim/psm_mac_collector.py` and `shim/collector.schema.json` into <out>
    3. Emit `<out>/SHA256SUMS` — one `<hex>  <name>` line per artifact,
       sorted, coreutils-compatible.

The wheel is reproducible w.r.t. the source tree because hatchling embeds the
pyproject version. The shim ships alongside the wheel because it runs on macOS
independently of the controller install.
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SHIM_FILES = (
    REPO / "shim" / "psm_mac_collector.py",
    REPO / "shim" / "collector.schema.json",
)


def build_wheel(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    cmd = [sys.executable, "-m", "build", "--wheel", "--outdir", str(out)]
    print(f"$ {' '.join(cmd)}", flush=True)
    subprocess.run(cmd, check=True, cwd=REPO)


def copy_shim(out: Path) -> list[Path]:
    copied: list[Path] = []
    for src in SHIM_FILES:
        if not src.exists():
            raise FileNotFoundError(f"missing shim file: {src}")
        dst = out / src.name
        shutil.copy2(src, dst)
        copied.append(dst)
    return copied


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write_checksums(out: Path) -> Path:
    artifacts = sorted(
        p for p in out.iterdir()
        if p.is_file() and p.name != "SHA256SUMS"
    )
    lines = [f"{sha256_file(p)}  {p.name}\n" for p in artifacts]
    dest = out / "SHA256SUMS"
    dest.write_bytes("".join(lines).encode("utf-8"))
    return dest


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the psm release bundle.")
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO / "dist",
        help="Output directory (default: ./dist).",
    )
    parser.add_argument(
        "--skip-wheel",
        action="store_true",
        help="Skip the wheel build (useful when iterating on the shim bundle).",
    )
    args = parser.parse_args()
    out = args.out.resolve()

    if not args.skip_wheel:
        build_wheel(out)

    copied = copy_shim(out)
    print(f"shim copied -> {[p.name for p in copied]}", flush=True)

    checksums = write_checksums(out)
    print(f"wrote {checksums}", flush=True)
    print(checksums.read_text(encoding="utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
