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

## Phase 3 — Hunt v1  ✅ COMPLETE (partial, see deferred)
- [x] artifacts populated from inventory (applications + files); installable files
      become `apk` artifacts
- [x] analyzers: `apk_flags` (DEBUGGABLE / TEST_ONLY / weak signing),
      `apk_source` (sideload), `apk_permissions` (6 permission combos +
      accessibility + device-admin)
- [x] findings upsert keyed on (artifact, analyzer, version, rule) — re-running is
      idempotent, bumping a version records a new row
- [x] `psm hunt [DEVICE]` / `psm hunt findings`
- [x] **Exit:** 64 findings over 514 artifacts in 0.09 s, no device access, no
      network. Correctly isolated the riskiest package on the phone
      (`com.silvertongue.paraphraser`: sideloaded + debuggable + accessibility
      service). 146 tests green, ruff + mypy strict clean.
- [ ] **deferred — APK pull** (`--pull-apks`): only adds signer-certificate detail
      beyond what the bulk dump already gives. Pull only flagged APKs when needed.
- [ ] **deferred — YARA**: new C dependency plus community rule sets whose yield
      against 140 personal PDFs is near-zero. Add when there is a concrete sample
      to match.
- [ ] **deferred — `psm hunt rescan`**: `psm hunt` is already re-runnable and
      idempotent, so a separate verb has nothing to do yet.
- [ ] **DECISION: root** — still non-root. Everything above works unrooted; only
      memory inspection and other apps' private storage need it. Unchanged
      recommendation: not worth a wipe + Play Integrity break.

### VirusTotal: wired but deliberately off
The ported client is hash-only and opt-in (`PSM_VT_API_KEY` + `--enrich vt`).
A full sweep of this device is 514 lookups; at the free tier's 4/min that is
132 minutes and over the 500/day cap, so VT can only ever be targeted at
artifacts a local analyzer already flagged — never a bulk scan. It is also the one
thing that leaves the Mac: a hash reveals possession of a file and VT logs queries.

### Found while building Phase 3
- Inventory stored only `system` from the dumpsys `flags` list, discarding
  DEBUGGABLE / TEST_ONLY — the two highest-signal manifest facts, already fetched
  for free. Now stored verbatim.
- **`installer is None` does not mean preinstalled.** `adb install` records no
  installer, so classifying on the installer alone labelled a sideloaded,
  debuggable app with an accessibility service as `preinstalled` — the most benign
  label available, for the riskiest package on the device. `classify_source` now
  reads the install path and SYSTEM flag too.

## Phase 4 — Flowlog: shared decoders + router leg  🟡 BUILT, LIVE TEST BLOCKED
- [x] decoders (stdlib only): pcap framing, IPv4/IPv6, TCP/UDP, DNS queries +
      A/AAAA answers, TLS SNI, ECH detection. Validated against **real** wire
      bytes — a 1525-byte OpenSSL ClientHello and a live resolver response
- [x] flow aggregator: packets folded to one row per (window, proto, remote,
      port, hostname); DNS cache for attribution; direction from local prefix
      with a well-known-port fallback
- [x] `hostname_source` persisted — `sni`/`dns-query` are observed, `dns-cache`
      is inferred, so a guess is never shown as a fact
- [x] hourly rollup + retention purge
- [x] `psm flow status|start|top|host|rollup`
- [x] 24 tests. Throughput **609,000 packets/s** end-to-end (target ≥ 2,000)
- [ ] **live capture NOT verified — blocked on hardware.** See below.

### Why leg A cannot run on this Mac
The only active interface is `en0` (Wi-Fi). macOS will not share a Wi-Fi uplink
back out over the same Wi-Fi radio, and there is no active Ethernet to share
*from* (`en1`–`en4` and `bridge0` are all inactive). So Internet Sharing cannot
create a hotspot for the phone to join, and there is no bridge to capture on.
`psm flow status` reports this rather than failing obscurely.

To unblock: a USB-C/Thunderbolt Ethernet adapter as the Mac's uplink, then share
Ethernet → Wi-Fi. Capture also needs `sudo` (the `admin` tier).

### Why this was still the right work
Both capture legs share these decoders. The on-device VPN leg reads raw IP packets
off a TUN, which is the same decode path with `LINKTYPE_RAW` instead of Ethernet —
already implemented and tested. Leg B needs no hardware and additionally supplies
the per-app attribution leg A cannot provide, so it is the better next step.

### Found while building Phase 4
- `rollup_flows` was **not idempotent**. SQLite treats NULLs as distinct in a
  UNIQUE index, so rows with no `app_pkg`/`hostname` never hit the ON CONFLICT
  target and were re-inserted — byte totals would have inflated on every run, and
  the CLI re-rolls every hour each invocation. Now delete-then-insert per hour.
- The `idna` codec rejects `errors="replace"`, so defensive SNI decoding crashed
  on the first real ClientHello. Hostnames are kept as ASCII punycode, which is
  also the honest form: `xn--80ak6aa92e.com` cannot be mistaken for `apple.com`.
- A pcap record split across two socket reads was being dropped; the reader now
  carries the partial tail forward.

## Phase 5 — Flowlog device leg + correlation  ✅ COMPLETE
**The VpnService agent was not built — it turned out not to be needed.**
`/proc/net/{tcp,tcp6,udp,udp6}` is readable over plain `adb exec-out` on a
non-rooted device and every row carries the owning UID, so per-app attribution
needs *nothing installed on the phone*.

- [x] `procnet.py` — /proc/net parser; little-endian word addresses, IPv4-mapped
      IPv6 collapse, TCP state decoding
- [x] `device.py` — DeviceSource polls over adb, diffs against the previous poll,
      emits new attributable connections; reverse DNS with a negative cache
- [x] UID → package from the application inventory already collected (`app_id`),
      no extra device round trip
- [x] `correlate.py` — joins the legs on (destination, time window): router
      hostnames fill device flows, device apps fill router flows; several apps to
      one address is left ambiguous rather than guessed
- [x] `psm flow start --leg device|router`, `psm flow correlate`, status covers both
- [x] 21 tests from real device rows; 191 total, ruff + mypy strict clean
- [x] **Exit (live on the phone):**
      `com.instagram.android → edge-mqtt-shv-02-bom5.facebook.com:443`
      `com.whatsapp          → whatsapp-cdn-shv-02-bom5.fbcdn.net:443`
      `com.google.android.gms → lcdels-in-f188.1e100.net:5228`
      `com.xiaomi.xmsf       → 20.157.92.101:5222`

### Why no agent is strictly better here
Keeps D4 (agentless) intact · nothing for MIUI to kill, which the user's own notes
flag as the main risk on a 4 GB device · no userspace packet forwarding, so a bug
cannot take the phone offline · works on mobile data, not only on a network we
control · no Kotlin app to build, sign, sideload, and maintain.

### What this leg cannot do (and the router leg must cover)
- **It samples live connections, it is not a complete log.** A socket opened and
  closed between polls is never seen. Poll cost is ~0.48 s, so ~1 s is the floor.
- **No per-connection byte counts.** /proc/net carries queue depths, not totals,
  so these flows store zero bytes. Volume comes from the router leg.
- **No DNS.** Hostnames here are reverse lookups (`hostname_source="rdns"`), which
  for CDN addresses often differ from the name the client asked for.

### Found while building Phase 5
- **Closing sockets lose their owner.** FIN_WAIT1 and LAST_ACK report `uid=0`
  because the kernel has dropped the owning process — 57 of 78 remote sockets on
  the test device. Emitting them would have invented 57 flows of apparent *root*
  network activity. Only attributable states are emitted; the rest are counted and
  reported so the blind spot stays visible.
- **Our own adb session is a socket on the phone** (uid 2000, com.android.shell)
  and accounted for 14 of 21 attributable connections — observer effect, not device
  behaviour. The controller's own addresses are excluded.
- Listening sockets are reported as state `0x8A`, not the standard `0x0A`; treating
  the high bit as part of the state dropped 72 of 150 rows.
- The IPv4-mapped IPv6 prefix word reads `FFFF0000`, not `0000FFFF`, because each
  word is little-endian. Hand-rolled IPv6 rendering was replaced with stdlib
  `ipaddress`, verified against the device's own link-local address.

## Phase 6 — macOS ESF stream  ← NEXT
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
