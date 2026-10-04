# CLAUDE.md

Guidance for Claude Code working in this repository.

## Project status

**v2 rewrite, in progress on branch `v2/mac-controller`.** Phases 0 (kernel
port + v1 defect fixes), 1 (macOS inventory) and 2 (Android inventory over
wireless ADB) and 3 (hunt) are complete; Phase 4 (flowlog, Mac-as-router leg) is
next. See `TODO.md` for progress.

v1 (branch `main`) was a working Windows-controlled tool — ~4,500 lines, 102
tests. It is **superseded, not deleted**: its proven core is being ported, its
Windows collector and SSH shim are not. v1 docs are archived in `docs/v1/`.

Read before making decisions:

- `AIM.md` — what this is, scope, and the limits that are platform properties
  rather than gaps to close
- `ARCHITECTURE.md` — three subsystems, two collection modes, data flow
- `HLD.md` — module map, decisions D1–D14, capability tiers, error philosophy
- `LLD.md` — schema, canonical JSON, interfaces, CLI spec, testing strategy
- `PLAN.md` — eight phases with exit criteria

## The two devices

| Name | Role | Reached via |
|---|---|---|
| `mac` | controller **and** target — MacBook Air M5, macOS 26 | in-process, no transport |
| `phone` | target — POCO M2 Pro, MIUI 14 / Android 12, 4 GB | wireless ADB + two capture legs |

No third device. No Windows. No iOS.

## The central structural rule

There are **two collection modes**, and conflating them is the mistake this
rewrite exists to correct:

```
poll   : collect() → items → diff(prev, cur) → events → rules → alerts
stream : subscribe() → records → detail table → rules → alerts
```

**A stream never goes through `diff()`.** Network flows and ESF events are
continuous; they have no "previous snapshot". Inventory is poll. Flowlog and ESF
are stream. Hunt is neither — it analyzes artifacts and produces findings.

## Three subsystems, one store

1. `inventory` — *what changed?* — snapshot → diff → events (ported from v1)
2. `hunt` — *is anything bad?* — artifact → analyzers → findings (new)
3. `flowlog` — *what is it talking to?* — continuous capture → flows (new)

Shared: SQLite store, hash chain, rules engine, CLI, reports, timeline.

## Key constraints

**Hash-chain the conclusions, not the firehose.** `events` is chained. `findings`
and `flows` are not — findings are re-evaluable by design, and chaining a
million flows a day would make `db verify` useless.

**`capabilities()` is derived from what actually collected**, never declared
from a constant. v1 declared optimistically and produced 64 phantom
"application removed" events in a single scan.

**A module returning zero items must prove it looked.** Distinguish "nothing
there" from "could not look" — every empty result needs either items or a
recorded gap. Three of v1's six defects were silent-empty bugs.

**Guard at the smallest unit that can fail.** One malformed plist must not zero
out a module. Catch broadly per item, narrowly everywhere else.

**Subject keys encode real identity, and it differs per platform.** macOS
permissions carry scope and target (TCC's primary key includes
`indirect_object_identifier`); macOS persistence carries scope; browser
extensions carry the profile. Android permissions stay `perm:<pkg>:<permission>`.
See LLD §3 — each widening fixed an actual collision on real data.

**Canonical JSON is frozen at v2** (sorted keys, no whitespace, UTF-8, floats
forbidden). `norm_path` is **platform-aware**: Windows folds and backslashes,
macOS NFC-normalizes and folds (APFS is case-insensitive), Android NFC-normalizes
without folding. v1 folded everything as Windows — that was a bug.

**Non-root Android.** Collectors declare `requires_tier`; `rooted` modules are
declared but unimplemented. Do not design anything that assumes root without
flagging it. Revisited at Phase 3.

**No TLS interception.** Metadata, DNS, and SNI only.

**VirusTotal is off by default and can never be a bulk scan.** 514 artifacts at
the free tier's 4 req/min is 132 minutes and over the daily cap. It is also the
only thing that leaves the Mac. Use it targeted, on artifacts a local analyzer
already flagged, behind `--enrich vt` and an explicit key.

**Hunt analyzers do no I/O.** They are pure functions of an artifact plus the
inventory payload already collected, which is what makes `psm hunt` re-runnable
offline in under a second. Anything needing the APK bytes is a separate opt-in
step.

**Android bulk reads, never per-package.** `dumpsys package <pkg>` costs 2.3 s
over wireless; one bulk `dumpsys package packages` covers all 373 packages in
5.7 s. Per-package loops are a ~14-minute scan.

**adb-over-TLS lies.** It returns truncated output with exit code 0, and throws
transient `protocol fault` errors. `adb.shell()` uses `exec-out` and retries
protocol faults; bulk package reads are cross-checked against an independent
`pm list` roster, because a short dump parses cleanly and would otherwise be
stored as a complete inventory.

## Conventions

- Python 3.12 (`uv` — there is no system 3.12), strict type hints
- No comments unless the *why* is non-obvious
- All timestamps UTC ISO-8601 with `Z`
- No ORM — hand-written SQL in `store/queries.py`
- SQLite WAL + foreign keys on at connection time
- Every subprocess call (`adb`, `eslogger`, `tcpdump`) goes through the one
  helper with timeout, output cap, and logged argv
- Exit codes: `0` clean · `1` error · `2` warnings/gaps · `3` alerts
- Data dir: `~/Library/Application Support/psm/`

## Commands

```bash
uv venv --python 3.12 && uv pip install -e ".[dev]"

psm doctor                  # which capability tiers are satisfied
psm baseline mac
psm scan phone
psm hunt phone --new
psm flow start
psm db verify

pytest
pytest -k test_diff
ruff check src/ && ruff format src/
```

## Environment

- `adb`: `/opt/homebrew/share/android-commandlinetools/platform-tools/adb`
  (v37.0.1) — **not on PATH**, use the full path or export `ANDROID_HOME`
- `JAVA_HOME=/opt/homebrew/opt/openjdk@17` — needed for the Kotlin agent (Phase 5)
- `eslogger` present with 104 ESF event types; needs FDA + root, SIP stays enabled
- Full Disk Access is **granted to Ghostty** — TCC and browser-profile reads work
- The filesystem is case-insensitive; `Foo.md` and `foo.md` are the same file

## What this is NOT

Not an antivirus. Not a continuous daemon on the controller (beyond the capture
legs). Not cloud-dependent. Not a GUI. No AI/ML classification — detection is
deterministic, rule-based, explainable, and local. VirusTotal enrichment is
hash-only and strictly opt-in.
