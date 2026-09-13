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

## Phase 0 — Kernel port + defect fixes  ✅ COMPLETE
- [x] pyproject (3.12, uv), ruff, pytest, `psm` entry point
- [x] Port canonical / chain / diff / rules / queries / report
- [x] Schema v2 (+ artifacts, findings, flows, flow_rollups; events.source/ref_id)
- [x] Data dir → `~/Library/Application Support/psm/`; v1 databases refused with
      an explanation rather than silently mis-diffed
- [x] `core/tiers.py` — base / fda / admin / rooted
- [x] Delete windows collector, shim, macOS SSH transport + ingest
- [x] Collector registry; orchestrator no longer hardcodes platforms
- [x] **F1** capabilities derived from `RawBundle.collected` (3 regression tests,
      incl. the 64-phantom-removal reproduction)
- [x] **F2** per-item guard contract + 2 regression tests (ExpatError pinned)
- [~] **F3** Chrome `Secure Preferences` — **moved to Phase 1**: the fix lives in
      the macOS browser collector, which Phase 1 builds. Nothing to fix yet.
- [x] **F4** dead process/network normalize paths removed with the shim ingest
- [x] **F5** file walk wired platform-agnostically (`DEFAULT_WALK`)
- [x] **F6** platform-aware `norm_path` + NFC (6 tests)
- [x] `psm --version`, `psm watch --before-after`, `psm persistence` — all three
      specified in v1 and never built
- [x] **Exit:** 86 passed / 0 failed · ruff clean · mypy strict clean (34 files)
      · `psm db verify` on a fresh DB returns 0

## Phase 1 — macOS inventory collector  ✅ COMPLETE
- [x] modules: apps / launchd (+ BTM login items) / tcc / files / browser
- [x] **F3** Chrome/Edge/Brave/Arc/Vivaldi/Opera `Secure Preferences` + 5 tests.
      Live result: **21 extensions found where v1 found 0**, 6 with broad host access
- [x] `normalize/macos.py` + 18 module tests from real-shaped fixtures
- [x] `psm doctor mac` — tier reporting (done in Phase 0)
- [x] scan report rendering
- [x] codesign-based signature status (~6 ms/binary); `spctl` deliberately not
      used in the walk at ~670 ms/call
- [x] builtin rules rewritten for macOS; `unknown` dropped from the unsigned-binary
      rule — it meant "we did not check", and alerting on that is not detection
- [x] **Exit:** LaunchAgent + unsigned binary → both surface, correlation alert
      fires on two independent paths (the plist and the BTM item macOS registers
      for it), removal detected, chain verifies. **9.7 s cold, 3.8 s warm**
      (target < 45 s). 104 tests green, ruff + mypy strict clean.

### Found while building Phase 1
- TCC `auth_value` is not a boolean: 0 denied · 2 allowed · 3/4/5 limited.
  v1's `bool(auth_value)` reported 5 limited grants as full ones.
- TCC's primary key includes `indirect_object_identifier`; the v1 subject key
  collided on the very first real database.
- `sfltool dumpbtm` nests `#n:` numbering inside `Embedded Item Identifiers`,
  which a naive record splitter turns into phantom entries.
- Chromium `manifest.theme` is usually `{}` — falsy, so a truth test fails to
  filter themes out of the extension list.

## Phase 2 — Android inventory collector  ← NEXT
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
- Full Disk Access: **granted to Ghostty** (2026-09-14) — TCC reads work;
  140 grants visible across the user and system databases

## Backlog (not before v2.0)
- [ ] Root-tier Android modules (memory, private storage)
- [ ] Windows as a target (reverse collector)
- [ ] Browser extension for per-tab attribution
- [ ] Timesketch export
- [ ] `psm db export --signed`
