# PSM — Implementation Guide

## 1. Stack

| Concern | Choice | Notes |
|---|---|---|
| Language (controller) | Python 3.12 on Windows | stdlib sqlite3, hashlib, winreg, subprocess cover most needs |
| CLI framework | typer | subcommands, completion, `--json` flags |
| Terminal output | rich | tables, severity colors (works in Windows Terminal) |
| Config/rules | PyYAML | rules and config.yaml |
| Packaging | pipx (`pyproject.toml`, hatchling) | single `psm` entry point |
| Windows collection | pinned osquery binary (vendored) + winreg/Get-AppxPackage | in-process on the controller |
| macOS collector | single-file stdlib-only Python shim | delivered over SSH or run manually |
| Android | adb.exe (platform-tools, detected or bundled) | agentless |
| Lint/format | ruff | CI-enforced |
| Tests | pytest + hypothesis | golden files + property tests |

No ORM. Hand-written SQL in `store/` keeps the schema honest and the hash chain explicit.

## 2. Repository Layout

```text
psm/
├── pyproject.toml
├── src/psm/
│   ├── __main__.py
│   ├── cli/
│   │   ├── app.py               # typer root, subcommand registration
│   │   └── render.py            # rich tables, severity styling
│   ├── core/
│   │   ├── models.py
│   │   ├── orchestrator.py
│   │   ├── diff.py
│   │   ├── rules.py
│   │   └── chain.py
│   ├── collectors/
│   │   ├── base.py
│   │   ├── windows/{collector.py, osquery.py, modules/*.py}
│   │   ├── android/{adb.py, collector.py, parsers/dumpsys_v33.py, dumpsys_v34.py}
│   │   └── macos/{transport.py, ingest.py}        # ssh/file transport + schema validation
│   ├── normalize/{windows.py, android.py, macos.py, canonical.py, paths.py}
│   ├── store/{db.py, migrations/, queries.py}
│   ├── report/{scan.py, daily.py, timeline.py, explain/, templates/}
│   └── enrich/{known_good.py, vt.py}
├── shim/psm_mac_collector.py    # single-file macOS collector (stdlib-only)
├── shim/collector.schema.json   # versioned output contract
├── rules/builtin/*.yaml
├── vendor/osquery/              # pinned osqueryi.exe + license
├── tests/
│   ├── fixtures/{windows/, android_33/, android_34/, macos/}
│   ├── test_diff.py
│   ├── test_chain.py
│   └── test_normalize_*.py
└── docs/{architecture.md, HLD.md, LLD.md, plan.md, todo.md}
```

## 3. Key Implementation Notes

### 3.1 canonical_json + path normalization (normalize/canonical.py, paths.py)
```python
import json, hashlib

def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def item_hash(payload: dict) -> str:
    return hashlib.sha256(canonical_json(payload).encode()).hexdigest()

def norm_path(p: str, platform: str) -> str:
    if platform == "windows":
        p = p.replace("/", "\\")
        if len(p) >= 2 and p[1] == ":":
            p = p[0].upper() + p[1:]
        return p.casefold()
    return p
```
Windows is case-insensitive: subject keys and rule joins always use `norm_path`, while the display payload keeps the original casing. Frozen after first release; any change requires a schema_version bump and a chain re-anchor migration.

### 3.2 osquery runner (collectors/windows/osquery.py)
`vendor/osquery/osqueryi.exe --json "<query>"` via the single subprocess helper (timeout, 64 MB output cap, logged command line). Version pinned; `psm doctor` verifies the binary hash. Queries live as named constants next to their normalizers so fixture tests pin both.

### 3.3 Hash walk with re-hash skip (collectors/windows/modules/files.py)
Keep a per-device cache table `(path_norm, size, mtime_ns, file_id) -> sha256` (file_id via `os.stat().st_ino`, which maps to the NTFS file index on Windows). On walk: stat first; hash only when the triple changed or the path is new. Respect `max_file_size_mb`; oversize files recorded with `sha256: null, skipped: "size"`. Expand `%VAR%` env references from config at load time.

### 3.4 Elevation handling
Detect elevation via `ctypes.windll.shell32.IsUserAnAdmin()`. Unelevated: HKLM run keys, services, and scheduled tasks may be partially readable — collect what's visible and record `CollectionGap("persistence", "not-elevated")`. `psm doctor` prints exactly what elevation adds; never auto-elevate.

### 3.5 ADB layer (collectors/android/adb.py)
- Locate `adb.exe` (config path → PATH → bundled platform-tools); wrap every call `adb -s <serial> shell <cmd>` with hard timeout + 8 MB output cap.
- Detect Android version first (`getprop ro.build.version.sdk`) and select the parser module by SDK level.
- Map ADB device states: `unauthorized` → "accept the prompt on the phone", `offline`/missing → OEM driver guidance in `psm doctor`.
- Any non-zero exit or parse failure is a CollectionGap, never a scan abort.

### 3.6 dumpsys parsing
State-machine parsers per SDK level over recorded fixtures. Never regex the whole blob; parse section headers (`Packages:`, `runtime permissions:`) then indentation-scoped bodies. Every parser has a golden test: `fixtures/android_34/dumpsys_package.txt → expected_items.json`.

### 3.7 macOS shim (shim/psm_mac_collector.py)
- Stdlib-only, single file, runs on macOS system `python3` (CLT). No pip installs on the Mac, ever.
- Emits the versioned envelope from LLD §3 on stdout; all diagnostics to stderr so SSH piping stays clean.
- TCC.db and browser SQLite files are copied to a temp dir before opening (locked/WAL); unreadable TCC → `gap("permissions","fda-missing")`.
- `codesign`/`spctl` run only on new/changed executables passed via the module args to keep runtime bounded.

### 3.8 SSH transport (collectors/macos/transport.py)
`ssh user@host 'python3 - --modules apps,persistence,…' < shim/psm_mac_collector.py` — the shim is piped, never installed, so the Mac keeps zero footprint. Uses the system `ssh.exe` (Windows 10+ ships OpenSSH client). Host key verification is left strict; first-connection instructions in docs. Output schema-validated against `collector.schema.json` before normalization; reject unknown module names; drop unknown payload fields.

### 3.9 Rules engine (core/rules.py)
Two passes over one event batch:
1. `match` rules: predicate tree (eq, in, prefix_any, exists) against `event.category/action` + payload; path predicates go through `norm_path`.
2. `correlate` rules: index batch by category, evaluate `join` expressions (a restricted `a.payload.X == b.payload.Y` form only — no eval).
Rules are validated at load; a broken user rule is skipped with a warning, never fatal.

### 3.10 Transactions & chain
All events of one diff insert inside one `BEGIN IMMEDIATE` transaction, ordered by (category, subject_key) for determinism, chain head updated last. Crash mid-transaction → nothing persisted, chain intact.

## 4. Conventions

- Type hints everywhere; `mypy --strict` on `core/` and `store/`.
- No code comments in committed code; names and tests carry the meaning.
- Every subprocess call (osquery, adb, ssh, PowerShell) goes through one helper with timeout, size cap, and logged command line.
- Timestamps: UTC ISO-8601 with `Z`, always.
- Data dir: `%LOCALAPPDATA%\psm\` (db, config.yaml, rules/, reports/, cache/).
- Errors shown to users are actionable ("Run `psm doctor`", "Enable Remote Login on the Mac: System Settings → General → Sharing").

## 5. CI (GitHub Actions)

- Windows runner: ruff, mypy, pytest (includes a self-scan e2e against a fixture tree + osquery smoke test).
- macOS runner: run the shim against the runner itself, schema-validate its output (contract test).
- Release job: build wheel, attach `psm_mac_collector.py` + checksums to the GitHub release.

## 6. Milestone → Code Mapping

| Plan phase | Primary modules touched |
|---|---|
| 0 | store/, core/chain.py, core/diff.py, core/models.py, normalize/paths.py |
| 1 | collectors/windows/, normalize/windows.py, cli/ |
| 2 | core/rules.py, report/explain/, rules/builtin/ |
| 3 | collectors/android/, normalize/android.py |
| 4 | shim/, collectors/macos/, normalize/macos.py |
| 5 | report/timeline.py, report/daily.py, browser modules |
| 6 | enrich/, hardening across ingest paths |
| 7 | docs, packaging |
