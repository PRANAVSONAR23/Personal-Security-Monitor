# PSM — High-Level Design (HLD)

## 1. Purpose

Define the modules, their responsibilities, interactions, and the major design decisions, without descending into schemas or function signatures (see LLD.md for those).

## 2. Module Map

```text
psm/
├── cli/            # argument parsing, output rendering
├── core/
│   ├── orchestrator.py
│   ├── models.py        # Device, Snapshot, InventoryItem, Event, Alert
│   ├── diff.py          # snapshot diff engine
│   ├── rules.py         # correlation rules (YAML-driven)
│   └── chain.py         # event hash chain
├── collectors/
│   ├── base.py          # Collector interface + capability negotiation
│   ├── windows/         # in-process: osquery runner + WMI/registry modules:
│   │                    #   apps, persistence, permissions(limited), files,
│   │                    #   network, browser, signatures(authenticode), processes
│   ├── android/         # adb wrapper + modules: packages, permissions,
│   │                    #   special_access, downloads, processes, netstats
│   └── macos/           # remote shim transport (ssh/file) + shim script:
│                        #   apps, persistence(launchd), permissions(TCC),
│                        #   files, network, browser, signatures(codesign)
├── normalize/           # raw → canonical items (per platform)
├── store/               # SQLite access layer, migrations
├── report/              # scan report, daily report, timeline, explain
└── enrich/              # local known-good hashes, optional VT hash lookup
```

## 3. Key Design Decisions

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | Snapshot-diff as v1 primitive (no daemons) | Cross-platform uniformity; matches "what changed after X" use case; drastically less platform code |
| D2 | Python 3.12 on the controller (Windows) | Fast iteration, rich stdlib (sqlite3, hashlib, winreg, subprocess); performance adequate for snapshot workloads |
| D3 | osquery as the local Windows collection engine | Battle-tested normalization of registry/services/tasks/ports; avoids fragile hand-written Win32 collection; runs in-process now that the controller is Windows |
| D4 | Agentless Android (ADB from the PC) | No persistent footprint on the phone; honest about non-root limits via capability negotiation |
| D5 | macOS as a stdlib-only single-file shim over SSH | macOS ships an SSH server (Remote Login) and Python-free delivery is one `scp`+`ssh` away; signature/TCC checks must run on the Mac anyway, so ship results as data |
| D6 | Capability negotiation per snapshot | Diffs only compare modules present in both snapshots → no false "removed everything" events when access differs |
| D7 | Append-only, hash-chained events table | Forensic credibility; detects post-hoc DB tampering |
| D8 | Rules as YAML data, not code | Users extend detection without touching source; rules are auditable |
| D9 | Content-addressed file records | File hash rows shared across snapshots → DB stays small over many scans |
| D10 | No listening network service on the controller | Minimizes attack surface; controller always initiates (SSH out, ADB out, local collection) |

## 4. Primary Use Cases → Flows

### UC1: First-time setup
`psm device add` → detect/register device → `psm baseline` → full snapshot stored and marked as baseline.

### UC2: "I clicked something sketchy" (on the Windows PC)
`psm watch --before-after` → snapshot A → user performs action → keypress → snapshot B → diff(A,B) → report. Highest-value flow; must complete in < ~60s locally.

### UC3: Routine check
`psm scan [device]` → diff against last snapshot (or baseline with `--against baseline`) → events + alerts → summary. For the Mac: `psm scan mac --ssh user@host` or `psm ingest macos FILE`.

### UC4: Investigation
`psm timeline --device win --last 7d`, `psm explain <event-id>`, `psm alerts`, `psm timeline export --format jsonl`.

### UC5: Daily report
Task Scheduler runs `psm scan --quiet && psm report daily` → markdown/text report written to reports dir.

## 5. Collection Scope per Platform (v1)

| Module | Windows (local, osquery+WMI) | macOS (SSH shim) | Android (ADB, non-root) |
|---|---|---|---|
| Applications | ✅ programs table, store apps | ✅ /Applications walk + system_profiler | ✅ pm list packages + dumpsys |
| Persistence | ✅ run keys, services, tasks, startup, WMI subs | ✅ launchd, login items, cron, profiles | ✅ device-admin, accessibility |
| Permissions | ⚠️ limited (app capabilities) | ✅ TCC.db (needs FDA on Mac) | ✅ per-app grants |
| Files (high-signal dirs) | ✅ hash walk | ✅ hash walk via shim | ⚠️ shared storage only |
| Signatures | ✅ Authenticode | ✅ codesign/notarization (runs on Mac) | ⚠️ APK signer only |
| Network state | ✅ listening_ports, open sockets | ✅ lsof snapshot | ⚠️ dumpsys netstats (coarse) |
| Browser | ✅ extensions, downloads, history DBs | ✅ same via shim | ❌ v1 |
| Processes | ✅ processes table | ✅ ps snapshot | ⚠️ partial |

✅ full, ⚠️ partial (recorded as capability), ❌ out of scope.

## 6. Event & Severity Model (summary)

Event = (device, ts, category, action, subject_key, before, after, snapshot_pair, severity).
Severity assigned by rules: `info` (app updated), `notice` (new app), `warning` (new persistence entry), `alert` (correlation hit). Full schema in LLD.

## 7. Error Handling Philosophy

- Partial collection is normal; every gap becomes a `collection_gap` record shown in the report header.
- Remote collector output is untrusted: schema-validate, size-limit, and timeout everything.
- The DB is sacred: all writes in transactions; `psm db verify` checks chain + FK integrity.

## 8. Performance Targets (v1)

- Windows full snapshot (default path set): < 60 s, < 500 MB RAM
- macOS snapshot over SSH (LAN): < 120 s including transfer
- Android snapshot: < 90 s over USB 2
- Diff of two 100k-item snapshots: < 5 s
- DB growth: < 20 MB per routine scan after content-addressing

## 9. Risks

| Risk | Mitigation |
|---|---|
| Admin/UAC prompts confuse users; partial data without admin | `psm doctor` explains what elevation adds; capability gaps shown in every report |
| FDA setup on the Mac is fiddly (granting to sshd-invoked python) | Documented setup path: grant FDA to Terminal + run shim manually once, or use the file-ingest mode; `doctor --ssh` verifies TCC readability |
| OEM ADB drivers missing on Windows | `psm doctor` detects "unauthorized/offline" states and links driver guidance |
| dumpsys format drift across Android versions | Version-keyed parsers + golden-file tests per Android release |
| Snapshot walk too slow on huge dirs | Configurable path set + size cap + mtime-based re-hash skip |
| Windows Defender flags the tool (hashing walks, osquery) | Code-sign the release later; document exclusion guidance; keep behavior transparent |
