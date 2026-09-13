# PSM — Architecture

## 1. System Overview

PSM is a hub-and-spoke system. The Windows controller owns all state, logic, and user interaction. Collectors are stateless data producers that emit standardized JSON. No collector writes to the database directly; all normalization and storage happens on the controller.

```text
┌───────────────────────── Windows Controller ──────────────────────────┐
│                                                                       │
│  ┌─────────┐   ┌────────────┐   ┌─────────────┐   ┌───────────────┐   │
│  │   CLI   │──▶│ Orchestr-  │──▶│  Collector  │──▶│  Normalizer   │   │
│  │  (psm)  │   │   ator     │   │  Adapters   │   │ (raw → event) │   │
│  └─────────┘   └────────────┘   └─────────────┘   └──────┬────────┘   │
│                      │                                   │            │
│                      ▼                                   ▼            │
│  ┌──────────────┐  ┌─────────────┐  ┌──────────┐  ┌────────────────┐  │
│  │ Report/      │◀─│ Diff Engine │◀─│ Snapshot │◀─│  SQLite Store  │  │
│  │ Timeline Gen │  │ + Rules     │  │  Store   │  │ (WAL, chained) │  │
│  └──────────────┘  └─────────────┘  └──────────┘  └────────────────┘  │
└───────────────────────────────────────────────────────────────────────┘
          ▲                      ▲                        ▲
          │ in-process           │ adb over USB           │ SSH / JSON file
   ┌──────┴──────┐        ┌──────┴───────┐        ┌───────┴────────┐
   │ Windows     │        │ Android      │        │ macOS          │
   │ Collector   │        │ Collector    │        │ Collector      │
   │ (osquery +  │        │ (agentless)  │        │ (remote shim)  │
   │  WMI/reg)   │        │              │        │                │
   └─────────────┘        └──────────────┘        └────────────────┘
```

## 2. Components

### 2.1 CLI (`psm`)
Single entry point. Subcommands: `device`, `baseline`, `scan`, `watch`, `persistence`, `timeline`, `report`, `explain`, `alerts`, `db`, `ingest`, `doctor`. Output: human-readable tables by default, `--json` for machine output.

### 2.2 Orchestrator
Resolves which device + collector to use, manages collector lifecycle (run local osquery collection, spawn ADB session, open SSH session to the Mac), enforces timeouts, and hands raw output to the Normalizer. Collection failures are partial-tolerant: a failed module (e.g., TCC.db unreadable on the Mac) is recorded as a `collection_gap`, never a silent omission.

### 2.3 Collector Adapters
One adapter per platform implementing a common interface:

```
collect(modules: [str], device: Device) -> RawBundle
capabilities(device: Device) -> [str]
```

`capabilities()` matters because Android non-root, Mac-with/without-FDA, and different OS versions expose different data. The diff engine only compares modules present in **both** snapshots.

### 2.4 Normalizer
Converts platform-raw output (osquery rows, registry dumps, `dumpsys` text, the Mac shim's JSON) into the canonical event/item schema. All platform knowledge about *format* lives here; the rest of the system is platform-agnostic.

### 2.5 Snapshot Store
A snapshot = set of normalized inventory items (files, apps, permissions, persistence entries, network state, extensions) tied to a device + timestamp + capability list. Stored fully in SQLite; large file-hash sets stored as content-addressed rows to deduplicate across snapshots.

### 2.6 Diff Engine
Compares two snapshots per module → emits events (added / removed / changed with attribute-level detail). Deterministic and pure: same two snapshots always produce the same events.

### 2.7 Rules / Correlation
Small built-in rule set evaluated over freshly emitted events, producing **alerts**:
- New executable, unsigned/invalid Authenticode, in a user-writable path
- New persistence entry (Run key, service, scheduled task) pointing at a file created in the same scan window
- New accessibility-service or device-admin grant (Android)
- New listening port from a process first seen this scan
Rules are data (YAML) so users can add their own.

### 2.8 Storage (SQLite)
Single database file, WAL mode. `events` is append-only with a hash chain: `row_hash = sha256(prev_hash ‖ canonical_json(event))`. `psm db verify` re-walks the chain.

### 2.9 Reporting / Timeline
- Scan report: what changed, grouped by severity/category.
- Daily change report: Task Scheduler-invokable `psm report daily`.
- Timeline: merged, time-ordered event view; export to JSONL (Timesketch-compatible).
- `psm explain <event-id>`: template-based plain-language context per event type.

## 3. Data Flow (scan)

```text
psm scan mac --ssh pranav@macbook.local
  1. Orchestrator: open SSH session (macOS built-in Remote Login)
  2. Collector: push/run shim script, receive JSON bundle on stdout
  3. Normalizer: shim JSON → inventory items
  4. Snapshot Store: persist snapshot N
  5. Diff Engine: diff(snapshot N-1 or baseline, snapshot N) → events
  6. Rules: events → alerts
  7. Store: append events (hash-chained) + alerts
  8. Report: render summary to terminal

psm scan windows   → same flow, steps 1–2 run in-process (osquery + WMI/registry)
psm scan android   → same flow, steps 1–2 via adb.exe over USB
```

## 4. Trust & Security Model

- Threat model: post-hoc inspection of a *possibly* compromised device from a *trusted* Windows PC. The controller is assumed clean; remote collectors run on untrusted hosts, so the controller treats collector output as data, never as code (no eval, strict schema validation).
- macOS shim output is schema-validated JSON; transport is SSH initiated *from* the controller, or a file copied by the user — no listening service on the controller in v1.
- Signature checks execute where they are meaningful: Authenticode locally on Windows; `codesign`/`spctl` inside the Mac shim (results shipped as data). Checking signatures of copied files cross-platform is invalid and is never done.
- The event hash chain gives tamper evidence, not tamper *proofing*; `psm db export --signed` can be added later.
- Privacy: no data leaves the controller by default. VirusTotal enrichment is hash-only and opt-in per invocation (`--enrich vt`).
- Note on self-inspection: when the controller scans itself (Windows scanning Windows), a sufficiently advanced compromise could lie to the scanner. This is inherent to any self-hosted tool; the before/after diff still catches the common cases (droppers, persistence, new binaries). For maximum trust, inspect the Windows PC's disk from another machine — out of scope for v1.

## 5. Deployment View

- Controller: Python 3.12 app, installed via pipx; data in `%LOCALAPPDATA%\psm\` (db, baselines, config.yaml, rules/); pinned osquery binary vendored alongside.
- Windows collection: in-process (same Python app); Administrator rights recommended for full registry/service coverage; degrades gracefully without (recorded as capability gap).
- Android: requires `adb.exe` (bundled check) + OEM USB driver where needed; USB debugging enabled on the phone.
- macOS: single-file shim (`psm-mac-collector.py`, stdlib-only) delivered over SSH each run or run manually; requires Full Disk Access granted to the invoking process (Terminal/sshd-wrapped python) for TCC coverage.

## 6. Non-Goals (v1)

- Real-time blocking/prevention of any kind
- Kernel-level monitoring (ETW deep integration, WFP, ESF) — Layer 2
- TLS interception
- iOS support
- Multi-user / remote server operation
