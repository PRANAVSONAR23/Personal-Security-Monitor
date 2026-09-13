# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Status

**This project is in the design phase.** No source code has been implemented yet. All architecture, schema, and implementation details are documented in the markdown files at the repo root. Phase 0 (foundations) is the first implementation milestone.

Design documents to read before making any decisions:
- `LLD.md` — SQLite schema, canonical JSON spec, diff algorithm, hash chain, CLI spec, rules engine, testing strategy
- `implementation.md` — Repository layout, stack choices, coding conventions, key implementation notes
- `HLD.md` — Module map, 10 design decisions (D1–D10), error philosophy, performance targets
- `plan.md` — 7 phases with exit criteria; `todo.md` for current progress

## Commands

Once Phase 0 scaffolding exists:

```bash
# Install (dev mode)
pipx install -e .

# Run
psm baseline
psm scan [DEVICE]

# Test
pytest
pytest -k "test_diff"          # run single test

# Lint / format
ruff check src/
ruff format src/
```

## Architecture

**Hub-and-spoke.** The Windows PC is the controller; all collectors are stateless data producers. The core loop is: **Collect → Normalize → Store → Diff → Report**.

```
Windows PC (Controller)
  CLI (typer) · SQLite · Diff Engine · Rules Engine · Report
       │
       ├── Windows Collector (in-process: osquery + winreg)
       ├── macOS Collector (SSH → single-file stdlib shim → ingest)
       └── Android Collector (ADB → dumpsys parsers)
```

**Planned layout:**
```
src/psm/
  cli/           # typer app + rich rendering
  core/          # models, orchestrator, diff, rules, hash chain
  collectors/    # windows/, android/, macos/ + base ABC
  normalize/     # per-platform raw→InventoryItem + canonical.py + paths.py
  store/         # db.py (SQLite), migrations/, queries.py (hand-written SQL, no ORM)
  report/        # scan, daily, timeline, explain templates
  enrich/        # known_good hashes + optional VirusTotal (hash-only)
shim/            # psm_mac_collector.py (stdlib-only, single file)
rules/builtin/   # YAML correlation rules
vendor/osquery/  # pinned osqueryi.exe
tests/
  fixtures/      # golden osquery/dumpsys/shim outputs
```

## Key Design Constraints

**Canonical JSON is a frozen spec** (sorted keys, no whitespace, UTF-8, floats as strings). Never change after v1.0 release — it is the basis for all item hashes and the hash chain.

**Windows path normalization**: lowercase drive letter, backslashes, case-folded. Applied before hashing so `C:\Foo` and `c:\foo` are the same item.

**Subject key format** (identity of every inventory item):
- `file:<abs-path>` · `pkg:<bundle-id>` · `persist:<platform>:<location>:<name>`
- `perm:<pkg>:<permission>` · `net:listen:<proto>:<port>:<process>`
- `ext:<browser>:<extension-id>` · `proc:<path>`

**Diff is a pure function**: `diff(snapA, snapB) → events`. It only compares modules present in both snapshots (capability negotiation) — never emits false "removed" events for uncollected data.

**Hash chain for tamper evidence**:
```
row_hash = sha256(prev_row_hash || canonical_json(event_core_fields))
```
`psm db verify` recomputes the full chain. `meta['chain_head']` tracks the head.

**Partial collection is normal**: gaps are recorded and surfaced in every report — no silent omissions.

## Coding Conventions (from `implementation.md`)

- Python 3.12, strict type hints everywhere
- No comments unless the WHY is non-obvious
- All timestamps UTC ISO-8601
- No ORM — hand-written SQL in `store/queries.py`
- SQLite WAL mode + foreign keys enabled at connection time
- osquery subprocess: 300 s timeout default, 64 MB stdout cap, JSON parsing
- macOS shim: stdlib-only, single file, no external deps
- Exit codes: 0 clean · 1 error · 2 warnings · 3 alerts

## What This Project Is NOT

Not an antivirus, not a continuous daemon, not cloud-dependent, not GUI-based. Detection is deterministic, rule-based, and fully local. VirusTotal enrichment is hash-only and strictly opt-in.
