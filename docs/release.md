# Release procedure

Cutting a psm release is intentionally small. There are exactly three artifacts:

- `psm-<version>-py3-none-any.whl` — the controller wheel.
- `psm_mac_collector.py` — the macOS shim, distributed as-is.
- `collector.schema.json` — the envelope schema the shim writes and the
  controller validates.

Plus one integrity file: `SHA256SUMS`.

## 1. Prerequisites

```powershell
# In your dev venv:
pip install build          # PEP 517 front-end used by tools/release.py
```

The full dev extras (`pip install -e ".[dev]"`) already give you pytest, ruff,
mypy, hypothesis — required for the pre-release checks below.

## 2. Pre-release checks

Everything must be green **before** you build the wheel.

```powershell
ruff check src/ tests/ shim/
ruff format --check src/ tests/ shim/
mypy                       # obeys pyproject `[tool.mypy]` files list
pytest -q
```

Exit criteria for the release:

- Zero ruff findings.
- Zero mypy findings in the strict scope (see `[tool.mypy]` in `pyproject.toml`).
- Full pytest suite green, including the hypothesis fuzz suite in
  `tests/test_shim_fuzz.py`.

## 3. Bump the version

Edit `src/psm/__init__.py` and `pyproject.toml` — both must match. Version
is `MAJOR.MINOR.PATCH`, no local segment, no `rc` suffix in v1 (dogfood on
`main` first).

## 4. Build the bundle

```powershell
python tools/release.py
# → dist/
#     psm-0.1.0-py3-none-any.whl
#     psm_mac_collector.py
#     collector.schema.json
#     SHA256SUMS
```

`SHA256SUMS` is coreutils-compatible: `sha256sum -c SHA256SUMS` on a Mac /
Linux, `Get-FileHash -Algorithm SHA256` on Windows.

## 5. Smoke test on a clean Windows

The pipx packaging exit-check requires a **clean** Windows profile (fresh user,
or a VM snapshot) — the goal is to catch missing runtime deps that your dev
box already has installed.

```powershell
# On the clean box:
python -m pip install --user pipx
python -m pipx ensurepath
# reopen shell
pipx install path\to\psm-0.1.0-py3-none-any.whl

psm --version
psm device add --name this-pc --platform windows
psm doctor this-pc
psm baseline this-pc
psm scan this-pc
psm db verify
```

All five commands must succeed. `psm db verify` must print `chain ok`.

## 6. Publish

For v1.0 the artifacts live under a GitHub release tag `v1.0.0`. Upload
`psm-*.whl`, `psm_mac_collector.py`, `collector.schema.json`, and
`SHA256SUMS`.

Users install with:

```powershell
pipx install https://github.com/<org>/psm/releases/download/v1.0.0/psm-1.0.0-py3-none-any.whl
```

and grab the shim + schema separately.

## 7. Post-release

- Tag `v<version>` in git.
- Bump `src/psm/__init__.py` and `pyproject.toml` to the next dev version
  (`0.1.1.dev0`) so nightly builds are distinguishable from the tagged
  release.
- Update `todo.md` — move any deferred items into the appropriate next-phase
  section.

## Signing (v1.1, deferred)

`psm db export --signed` will emit a `.psm-export` file plus a minisign
detached signature. The public key ships in the release bundle. This closes the
"attacker replaces the whole DB" gap called out in `docs/threat-model.md`.
