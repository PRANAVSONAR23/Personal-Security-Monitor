# PSM v2 — High-Level Design

## 1. Module map

```text
src/psm/
├── cli/                 # typer app, rich rendering
├── core/
│   ├── models.py        # Device, Snapshot, InventoryItem, Event, Finding, Flow, Alert
│   ├── diff.py          # PORTED  pure snapshot diff
│   ├── chain.py         # PORTED  event hash chain
│   ├── rules.py         # PORTED+ YAML rules, extended to 3 record types
│   └── tiers.py         # NEW     capability tiers (unrooted / rooted / fda / admin)
├── collectors/          # poll mode — Adapter
│   ├── base.py
│   ├── macos/           # NEW  in-process: apps, launchd, tcc, files, browser
│   └── android/         # PORTED+ adb: packages, permissions, special_access,
│                        #         storage, downloads
├── streams/             # stream mode — Producer                          NEW
│   ├── base.py          # StreamSource, supervisor, restart + gap recording
│   ├── esf.py           # macOS: eslogger subscription
│   └── netflow/
│       ├── router.py    # leg A: pcap on the Internet Sharing interface
│       ├── device.py    # leg B: VpnService log pulled over adb
│       └── correlate.py # join legs on (ts window, destination)
├── hunt/                # analysis — Strategy                             NEW
│   ├── base.py          # Analyzer ABC, Artifact, Finding
│   ├── yara_rules.py
│   ├── apk.py           # manifest, permissions, signer, dex heuristics
│   ├── known_good.py    # PORTED
│   └── vt.py            # PORTED  hash-only, opt-in
├── normalize/           # raw → canonical
│   ├── canonical.py     # PORTED  frozen spec
│   ├── paths.py         # PORTED+ made platform-aware (v1 bug)
│   ├── macos.py         # NEW
│   └── android.py       # PORTED
├── store/               # hand-written SQL, no ORM
│   ├── db.py            # PORTED+ data dir → ~/Library/Application Support/psm
│   ├── migrations/
│   └── queries.py       # PORTED+ new tables
└── report/              # PORTED  scan, daily, timeline, explain

agent/android-vpn/       # NEW  the on-device VpnService app (Kotlin)
rules/                   # YAML: detection rules
yara/                    # YARA rule sets
```

**Deleted from v1:** `collectors/windows/`, `collectors/macos/transport.py`
(SSH), `collectors/macos/ingest.py`, `shim/`.

The v1 macOS shim is not ported as a shim — its *collection logic* (launchd
plist parsing, TCC reads, browser profile parsing, app bundle walking) is lifted
into `collectors/macos/` as in-process modules. Same knowledge, no JSON round
trip, testable directly.

## 2. Design decisions

| # | Decision | Rationale |
|---|---|---|
| **D1** | Mac is controller **and** target; collection there is in-process | No transport layer for the device I use most. The v1 SSH shim existed only because the controller was Windows |
| **D2** | Three subsystems (inventory / hunt / flowlog), one shared store | They answer genuinely different questions with different data models. Merging them would distort all three |
| **D3** | Two collection modes: **poll** and **stream**. A stream never goes through `diff()` | Continuous telemetry has no "previous snapshot". This is the structural lesson of v1 |
| **D4** | Hash-chain the conclusions (`events`), not the firehose (`flows`) | `db verify` must stay fast and meaningful. Chaining 10⁶ flows/day protects nothing an attacker would target |
| **D5** | Capability **tiers**, root-aware from day one | Android modules declare `requires_tier`. Unrooted is the default, complete, supported path; rooted modules slot in without touching the interface |
| **D6** | `capabilities()` is derived from what *actually collected*, never declared | v1 declared optimistically and emitted 64 phantom "application removed" events in one scan when a module was absent. Reproduced and verified |
| **D7** | Network capture is **two-legged and correlated** | Router leg gives hostnames with zero phone footprint; device leg gives per-app attribution. Each covers the other's blind spot, and either alone is a valid degraded mode |
| **D8** | No TLS interception, by default or otherwise | Pinning breaks, privacy stance conflicts. SNI + DNS + metadata is the honest ceiling |
| **D9** | Hunt findings are **versioned and re-evaluable** | Analyzers improve. `(artifact, analyzer, analyzer_version) → verdict` makes re-running idempotent and the delta meaningful |
| **D10** | Every finding and alert names its analyzer, rule, and evidence | Explainability is the product. An unexplainable verdict is worse than no verdict |
| **D11** | macOS kernel telemetry via `eslogger`, SIP stays **enabled** | 104 ESF event types with FDA + root, no Apple entitlement. A real ESF system extension needs provisioning we cannot get |
| **D12** | Path normalization is **platform-aware** | v1 casefolded every path as Windows, including on case-sensitive macOS. Frozen spec, but the freeze was wrong and this is the moment to fix it |
| **D13** | Partial collection is normal; a silently empty module is a **bug** | v1's browser module returned 0 extensions while 10 existed, recording no gap. Every module must distinguish "nothing there" from "could not look" |
| **D14** | No ORM; hand-written SQL | Keeps the schema and the hash chain explicit |

## 3. Capability tiers

A tier is a *precondition*, not a platform. Modules declare what they need; the
collector reports which tiers are currently satisfied.

| Tier | Device | How it's satisfied | Unlocks |
|---|---|---|---|
| `base` | both | always | apps, packages, persistence, permissions, public storage |
| `fda` | mac | Full Disk Access granted to the terminal | TCC.db, browser profiles, protected paths |
| `admin` | mac | running as root | `eslogger` ESF stream, pcap on the hotspot interface |
| `rooted` | phone | root (not currently satisfied, by choice) | other apps' private storage, memory inspection, kernel hooks |

`psm doctor` reports which tiers are live and states exactly what each missing
tier would add — never auto-escalating.

Modules gated behind `rooted` are **declared but unimplemented** in v2. The
interface is root-aware so the decision can be revisited at Phase 3 without a
refactor.

## 4. Error philosophy

- **A gap is a first-class record**, not a log line. Every module that fails to
  produce output records `(module, reason, detail)` and it surfaces in every
  report that covers that window.
- **"Empty" and "failed" are different.** A module returning zero items must
  prove it looked. This was v1's most damaging bug class.
- **A module failure never aborts a run.** One bad plist must not zero out the
  persistence module — v1 lost all 471 launchd entries to a single malformed
  system plist because the guard sat at module level instead of per-item.
- **Guard at the smallest unit that can fail**, and catch broadly there
  (`except Exception`), narrowly everywhere else.
- **Stream sources dying is normal.** MIUI kills background services under
  memory pressure. The supervisor restarts and records the gap window.

## 5. Performance targets

| Operation | Target |
|---|---|
| macOS inventory snapshot (default paths) | < 45 s |
| Android inventory snapshot over wireless ADB | < 90 s |
| `diff()` of two 100k-item snapshots | < 5 s |
| `psm db verify` (chained events only) | < 2 s at 10⁵ events |
| Flow ingest sustained | ≥ 2k flows/s without drop |
| Flow storage after rollup | < 50 MB / week |
| APK analysis (manifest + signer + YARA) | < 3 s per APK |

## 6. Risks

| Risk | Mitigation |
|---|---|
| MIUI kills the VpnService agent | Router leg keeps working independently; supervisor restarts; gap recorded. Document battery-optimization + autostart pinning |
| ECH / DoH blind the router leg | Degrade to IP+port, record the degradation explicitly. Document Private DNS = off |
| Wireless ADB drops / re-pair needed | `psm doctor phone` detects and walks through `adb pair`; never silently half-collects |
| Flow table growth | Retention policy + hourly rollup + `psm db compact` |
| YARA false positives | Findings are advisory and evidence-bearing; known-good hash suppression; nothing is ever auto-removed |
| Self-inspection ceiling on the Mac | Documented, not hidden. `eslogger` raises it; nothing removes it |
| Porting bugs from v1 | The 6 known v1 defects are tracked as explicit Phase 0 fix items with regression tests |
