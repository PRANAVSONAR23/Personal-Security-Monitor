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

## Phase 2 — Android inventory collector  ✅ COMPLETE
- [x] adb ported to macOS (`adb.exe` → `adb`, ANDROID_HOME discovery); wireless
      pairing verified against the POCO
- [x] **one bulk `dumpsys package packages`** instead of per-package calls
- [x] modules: packages / permissions / special_access / storage
      (downloads folded into storage — /sdcard/Download is one of its roots)
- [x] Android 31 (MIUI 14) fixture + 22 module tests + 4 e2e tests
- [x] `psm doctor phone` — tiers, adb state, wireless re-pair guidance
- [x] **Exit:** planted an installable file in /sdcard/Download → surfaced as a
      `warning` via the new rule, removal detected, chain verifies.
      **5.7 s cold, 4.0 s warm** (target < 90 s). 1,257 items: 743 permissions,
      373 applications, 141 files. 124 tests green, ruff + mypy strict clean.

### Found while building Phase 2
- **Per-package `dumpsys` is unusable over wireless.** 2.3 s per call × 373
  packages ≈ 14 min. v1 issued two per package. One bulk call is 5.7 s.
- **adb-over-TLS returns truncated output with exit code 0.** One run yielded 295
  of 373 packages, parsed cleanly, and would have been stored as the complete
  inventory — every later scan then reporting the missing 78 as newly installed.
  Guarded by cross-checking against an independent `pm list` roster.
- adb-over-TLS also throws transient `protocol fault (status 17 03 03 00?!)`;
  `shell()` now uses `exec-out` and retries protocol faults.
- v1's parser read `appId=`, which does not exist on this device (`userId=`), so
  its app-id field was always None.
- `com.xiaomi.discover` (36 apps), `com.facebook.system` (3) and
  `com.miui.analytics` (1) were unmapped installers → classified `unknown` →
  the sideload rule matched `unknown` → **40 false alerts on the first scan**.
  Installer map extended; rule narrowed to `sideload` only.
- Wireless adb serials (`IP:port`) rotate whenever wireless debugging is
  toggled, so the stored identifier goes stale. mDNS advertises a stable name but
  proved flaky in testing, so re-pairing stays manual for now.

## Phase 3 — Hunt v1  ← NEXT
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
- phone paired over wireless debugging; serial `192.168.1.6:42137` (rotates on toggle)
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
