# PSM v2 — Progress

`[ ]` not started · `[~]` in progress · `[x]` done · `[!]` blocked

## Decisions locked (2026-09-14)

- Controller **and** target: the Mac. Second target: the POCO M2 Pro (MIUI 14 /
  Android 12, 4 GB). No third device, no Windows.
- Android stays **non-root**; collectors are tier-aware so root modules can slot
  in later. Revisited at Phase 3.
- Network capture is **two-legged**: Mac-as-router + on-device VpnService,
  correlated on (ts, destination).
- Rewrite the docs and the collector layer; **port** the proven v1 kernel
  (canonical, chain, diff, rules, store, report).

## Phase 0 — Kernel port + defect fixes
- [ ] pyproject (3.12, uv), ruff, pytest, `psm` entry point
- [ ] Port canonical / chain / diff / rules / queries / report
- [ ] Schema v2 (+ artifacts, findings, flows, flow_rollups; events.source/ref_id)
- [ ] Data dir → `~/Library/Application Support/psm/`
- [ ] `core/tiers.py`
- [ ] Delete windows collector, shim, macOS SSH transport + ingest
- [ ] **F1** capabilities derived from `RawBundle.collected` + regression test
- [ ] **F2** per-item guards + regression test (malformed plist)
- [ ] **F3** Chrome `Secure Preferences` + regression test
- [ ] **F4** remove dead process/network normalize paths
- [ ] **F5** wire macOS file walk through the CLI
- [ ] **F6** platform-aware `norm_path` + NFC
- [ ] `psm --version`, `psm watch --before-after`, `psm persistence`
- [ ] **Exit:** pytest green incl. 6 regression tests; chain verifies

## Phase 1 — macOS inventory collector
- [ ] modules: apps / launchd / tcc / files / browser (incl. Brave)
- [ ] `normalize/macos.py` + golden fixtures from this machine
- [ ] `psm doctor mac` — tier reporting
- [ ] scan report rendering
- [ ] **Exit:** LaunchAgent + unsigned binary surface as events, < 45 s

## Phase 2 — Android inventory collector
- [ ] adb wrapper + `adb pair`/`connect` flow (wireless)
- [ ] **single-pass** `dumpsys package` (v1 called it 2×/package)
- [ ] modules: packages / permissions / special_access / storage / downloads
- [ ] Android 12 (MIUI 14) golden fixtures
- [ ] `psm doctor phone` + MIUI guidance
- [ ] **Exit:** APK install + permission grant → exact events, < 90 s

## Phase 3 — Hunt v1
- [ ] artifacts table populated from inventory
- [ ] APK pull → staging
- [ ] analyzers: yara / apk_manifest / apk_signer / known_good / vt
- [ ] findings upsert + promotion to chained events
- [ ] `psm hunt` / `hunt findings` / `hunt rescan`
- [ ] **DECISION:** revisit root
- [ ] **Exit:** test APK produces evidence-bearing findings

## Phase 4 — Flowlog leg A (Mac-as-router)
- [ ] Internet Sharing detection + doctor check
- [ ] pcap capture on the hotspot interface
- [ ] decoders: DNS, TLS SNI (+ ECH detection), flow tuples, byte counts
- [ ] flows writer + hourly rollup + retention
- [ ] `psm flow top` / `flow host`
- [ ] **Exit:** 5 min browsing → correct hostnames, ≥ 2k flows/s

## Phase 5 — Flowlog leg B (device agent) + correlation
- [ ] `agent/android-vpn/` Kotlin VpnService, local-only
- [ ] per-UID attribution + package resolution
- [ ] log pull over adb + hostile-input parser
- [ ] correlator; unattributed flows survive
- [ ] supervisor restart + gap recording (MIUI kills)
- [ ] MIUI setup doc
- [ ] **Exit:** `psm flow app com.whatsapp` works; agent death = gap, not loss

## Phase 6 — macOS ESF stream
- [ ] `streams/esf.py` via eslogger
- [ ] event subset + volume control
- [ ] rules over ESF records
- [ ] **Exit:** LaunchAgent add detected in seconds

## Phase 7 — Polish
- [ ] unified timeline with `--source`
- [ ] `psm report daily` + launchd sample
- [ ] explain templates for new event types
- [ ] setup docs (FDA, wireless adb, MIUI, Internet Sharing)
- [ ] rewrite CLAUDE.md
- [ ] dogfood 1 week → tag v2.0

## Environment notes
- `adb`: `/opt/homebrew/share/android-commandlinetools/platform-tools/adb` (v37.0.1), not on PATH
- `ANDROID_HOME=/opt/homebrew/share/android-commandlinetools`
- `JAVA_HOME=/opt/homebrew/opt/openjdk@17` (needed for the Kotlin agent, Phase 5)
- No system Python 3.12 — use `uv`
- `eslogger`: present, 104 event types. SIP enabled, keep it that way
- Full Disk Access: **not yet granted** — TCC reads currently fail

## Backlog (not before v2.0)
- [ ] Root-tier Android modules (memory, private storage)
- [ ] Windows as a target (reverse collector)
- [ ] Browser extension for per-tab attribution
- [ ] Timesketch export
- [ ] `psm db export --signed`
