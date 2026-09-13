# PSM v2 — Plan

Eight phases. Each ends with something runnable on real hardware (this Mac, that
phone). Order front-loads the two features that motivated the rewrite while
respecting the dependency that hunt and flowlog both need the store first.

## Phase 0 — Kernel port + v1 defect fixes

**Goal: the shared foundation, with every known v1 bug fixed on the way in.**

1. New `pyproject.toml`, Python 3.12 via `uv`, ruff, pytest, `psm` entry point.
2. Port intact: `normalize/canonical.py`, `core/chain.py`, `core/diff.py`,
   `core/rules.py`, `store/queries.py`, `report/`.
3. Schema v2: ported tables + `artifacts`, `findings`, `flows`, `flow_rollups`;
   `events.source`, `events.ref_id`; `snap_to` nullable.
4. `store/db.py` data dir → `~/Library/Application Support/psm/`.
5. `normalize/paths.py` → platform-aware + NFC (LLD §2).
6. `core/tiers.py` — tier model.
7. Delete `collectors/windows/`, `shim/`, macOS SSH transport + ingest.

**Fix list carried from v1, each with a named regression test:**

| # | Defect | Fix |
|---|---|---|
| F1 | `capabilities()` declared, not derived → 64 phantom "removed" events | `RawBundle.collected` drives `snapshots.capabilities` |
| F2 | One malformed plist zeroed the whole persistence module (471 → 0) | Guard per item, `except Exception`, emit N-1 + gap |
| F3 | Chrome extensions read from `Preferences`, not `Secure Preferences` → 0 of 10 found, no gap | Read both; record a gap when neither is readable |
| F4 | Shim collected processes + network; normalizer silently discarded both | Either normalize them or don't collect them — no dead paths |
| F5 | macOS file walk unreachable from the CLI | Wire `file_walk` for both platforms |
| F6 | `norm_path` casefolded every path as Windows | D12 / LLD §2 |

Also: add `psm --version` (v1 shipped a testing doc whose step 3 fails), and
implement `psm watch --before-after` and `psm persistence`, both specified in v1
and never built.

**Exit:** `pytest` green including all six regression tests; synthetic snapshots
diff; chain verifies; `psm db verify` on an empty DB succeeds.

## Phase 1 — macOS inventory collector (local, in-process)

**Goal: `psm baseline mac` / `psm scan mac` / `psm watch --before-after`.**

1. Lift the v1 shim's collection logic into `collectors/macos/modules/`:
   `apps` (bundle walk + `Info.plist`), `launchd` (LaunchAgents/Daemons/login
   items/cron), `tcc` (copy-then-read TCC.db), `files` (hash walk + skip cache),
   `browser` (Chrome/Edge/**Brave**/Firefox/Safari — with the F3 fix).
2. `normalize/macos.py`, golden fixtures recorded from this machine.
3. `psm doctor mac` — reports `base` / `fda` / `admin` tiers and what each adds.
4. Terminal scan report rendering.

**Exit:** baseline → plant a LaunchAgent + drop an unsigned binary in
`~/Downloads` → scan surfaces both as events, < 45 s, chain verifies. The 10
real Chrome extensions on this machine are collected (F3 regression).

## Phase 2 — Android inventory collector (wireless ADB, non-root)

**Goal: `psm baseline phone` / `psm scan phone`.**

1. ADB wrapper: discovery (`$ANDROID_HOME/platform-tools/adb`), `adb pair` /
   `adb connect` flow, timeouts, output caps, SDK detection.
2. **Single-pass `dumpsys package`** — v1 called it twice per package
   (~400 round trips for 200 apps). One call, parsed once, fanned out to both
   the application and permission categories.
3. Modules: `packages`, `permissions`, `special_access` (accessibility /
   device-admin), `storage` (shared storage walk), `downloads`.
4. Version-keyed `dumpsys` parsers + golden fixtures from Android 12 (MIUI 14).
5. `psm doctor phone` — pairing state, unauthorized/offline, MIUI-specific
   guidance from the Silvertongue notes.

**Exit:** baseline → sideload an APK + grant a permission → scan shows exactly
those events, < 90 s over wireless.

## Phase 3 — Hunt v1

**Goal: `psm hunt phone --new` finds something real.**

1. `artifacts` population from inventory file + application items.
2. APK pull over adb into `staging/`.
3. Analyzers: `yara` (file + APK), `apk_manifest` (dangerous permission combos,
   exported components, debuggable/backup flags), `apk_signer` (signature
   scheme, self-signed, cert age), `known_good` (hash suppression),
   `vt` (hash-only, opt-in).
4. `findings` persistence + upsert semantics; alert-severity findings promoted
   to chained events.
5. `psm hunt findings` / `psm hunt rescan`.

**Decision point:** revisit root. Everything above works unrooted. Memory
inspection and other apps' private storage do not, and this is where that
trade-off becomes concrete.

**Exit:** a deliberately sideloaded test APK with an over-broad permission set
produces findings naming the analyzer, rule, and evidence. A known-good hash
suppresses its finding while the artifact still appears.

## Phase 4 — Flowlog leg A: Mac-as-router

**Goal: `psm flow start` with zero footprint on the phone.**

1. Internet Sharing setup + detection; `psm doctor` verifies the hotspot
   interface and `admin` tier.
2. pcap capture on that interface (needs root).
3. Decoders: DNS queries/responses, TLS ClientHello SNI (record `ech` when the
   hello is encrypted), TCP/UDP flow tuples + byte counts.
4. `flows` writer with backpressure; hourly rollup; retention policy.
5. `psm flow top` / `psm flow host`.

**Exit:** phone on the hotspot, browse for 5 minutes, `psm flow top --by host`
shows the hostnames actually visited. Sustained ≥ 2k flows/s without drop.

## Phase 5 — Flowlog leg B: on-device agent + correlation

**Goal: per-app attribution.**

1. `agent/android-vpn/` — minimal Kotlin `VpnService`, local-only (no remote
   endpoint), writes a structured flow log to app-private storage.
2. Per-UID attribution via `ConnectivityManager.getConnectionOwnerUid` with a
   `/proc/net` fallback; UID → package resolution.
3. Log pulled over adb; hostile-input-tolerant parser.
4. `streams/netflow/correlate.py` — join legs on `(ts window, dst)`. Unmatched
   flows survive as unattributed; never dropped.
5. Supervisor: restart on MIUI kill, record the gap window.
6. MIUI setup doc — battery optimization off, autostart on.

**Exit:** `psm flow app com.whatsapp --last 24h` lists hostnames. Killing the
agent produces a recorded gap, not silent data loss, and the router leg keeps
running.

## Phase 6 — macOS ESF stream (`eslogger`)

**Goal: kernel-level telemetry on the Mac.**

1. `streams/esf.py` — subscribe via `eslogger`, parse the JSON stream.
2. Event subset: `exec`, `btm_launch_item_add`, `remote_thread_create`,
   `cs_invalidated`, `xp_malware_detected`, `mount`, `kextload`, `profile_add`.
3. Volume control — `exec` alone is thousands/hour; filter and aggregate at the
   source, not after writing.
4. Rules over ESF records.

**Exit:** adding a LaunchAgent produces a `btm_launch_item_add` event *within
seconds*, versus the next scan. XProtect verdicts land in the timeline.

## Phase 7 — Reports, timeline, polish

1. Unified timeline across all four sources; `--source` filter.
2. `psm report daily` + a launchd plist sample for scheduling.
3. `psm explain` templates for the new event types.
4. Setup docs: FDA, wireless ADB pairing, MIUI quirks, Internet Sharing.
5. Rewrite `CLAUDE.md` for the shipped architecture.
6. Dogfood one week; fix the top annoyances; tag v2.0.

## Working agreements

- Every module lands with fixtures + tests in the same commit.
- No phase starts before its exit criteria are written into `TODO.md`.
- **A module that returns zero items must prove it looked** (D13). This is the
  single rule that would have caught three of the six v1 defects.
- Live-verify on real hardware before marking a phase done. Unit tests are
  necessary, not sufficient — every v1 defect I found passed its own test suite.
