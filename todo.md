# PSM — TODO / Progress Tracker

Status legend: `[ ]` not started · `[~]` in progress · `[x]` done · `[!]` blocked

## Phase 0 — Foundations
- [x] Repo scaffold (pyproject, ruff, pytest, `psm` entry point on Windows)
- [x] SQLite schema + migrations (LLD §1)
- [x] canonical_json + item_hash + norm_path (frozen spec, Windows casing rules)
- [x] Event hash chain + `psm db verify`
- [x] Core models (Device, Snapshot, InventoryItem, Event, Alert)
- [x] Diff engine + property tests (diff(A,A)==∅, tamper test)
- [x] **Exit check:** synthetic snapshot diff passes in tests

## Phase 1 — Windows Collector MVP (local, in-process)
- [ ] Vendor pinned osquery + runner (timeout, output cap, binary-hash check)
- [x] Collector base interface + capability negotiation
- [~] Module: persistence (Run keys ✓; services, scheduled tasks, startup, WMI subs deferred)
- [~] Module: apps (Uninstall keys ✓; Get-AppxPackage deferred)
- [x] Module: files (hash walk + mtime/file_id skip cache + size cap)
- [ ] Module: signatures (authenticode on new/changed executables)
- [ ] Module: processes
- [ ] Module: network (listening_ports + open sockets)
- [x] Golden-file fixtures + normalizer tests (Windows)
- [x] Elevation detection + `psm doctor` (explains what admin adds)
- [~] CLI: device add ✓ / baseline ✓ / scan ✓ / watch --before-after deferred
- [x] Terminal scan report rendering
- [x] **Exit check:** UC2 end-to-end < 60 s; planted file surfaces as event, chain verifies

## Phase 2 — Rules, Alerts, Explain
- [x] YAML rules loader + validation
- [x] Match engine (eq / in / prefix_any / exists, path-normalized)
- [x] Correlate engine (restricted joins)
- [x] 5 built-in rules shipped
- [x] Alerts table + `psm alerts` (open/ack/close)
- [x] `psm explain` templates for top 8 event types
- [x] Severity in report + exit code 3 on alerts
- [x] **Exit check:** unsigned exe in user path + Run-key entry → correlated + unsigned alerts

## Phase 3 — Android Collector
- [x] adb.exe discovery (config → PATH → bundled) + wrapper (timeouts, size caps, SDK detection)
- [x] `psm doctor` android checks (unauthorized/offline states, OEM driver guidance)
- [x] Module: packages (pm list + dumpsys parser, installer classification)
- [x] Module: permissions (runtime perms parsed from dumpsys)
- [x] Module: special_access (accessibility, device-admin)
- [ ] Module: downloads (shared storage) — deferred
- [ ] Module: netstats — deferred
- [x] Fixtures: Android 13 + 14 dumpsys golden files
- [x] Rules: new accessibility grant; sideloaded install
- [x] **Exit check:** APK install + permission grant appear as exact events

## Phase 4 — macOS Collector Shim
- [x] psm_mac_collector.py (single file, stdlib-only): apps, persistence, TCC, files, lsof, processes
  - [ ] codesign / browser modules — deferred to Phase 5
- [x] collector.schema.json + versioning
- [x] SSH transport (`psm scan mac --ssh user@host`, shim piped via stdin)
- [x] `psm ingest macos FILE` (manual mode)
- [x] `psm doctor mac` (advises to run a scan for full readiness signal)
- [ ] FDA + Remote Login setup docs — deferred to Phase 7 (docs)
- [x] Fixtures + normalizer tests (macOS shim output)
- [x] **Exit check:** from the PC, ingest a baseline shim envelope, ingest a scan envelope with a new LaunchAgent → persistence event appears, chain verifies

## Phase 5 — Timeline, Reports, Browser
- [x] Timeline query + filters (device/last/category)
- [x] Timeline export JSONL (Timesketch mapping)
- [x] `psm report daily` + Task Scheduler XML sample (docs/samples/psm-daily.xml)
- [x] Browser module Windows (Chrome/Edge/Firefox extensions — Preferences + extensions.json)
- [x] Browser module macOS (shim: Chrome/Edge/Firefox/Safari)
  - [ ] downloads history — deferred
- [x] Rule: `new-browser-extension-all-urls` (has_any predicate added to rules engine)
- [x] **Exit check:** planting a broad-permission Chrome extension surfaces as a browser-added event and triggers the built-in alert; timeline JSONL round-trip validates Timesketch fields; daily report renders

## Phase 6 — Enrichment & Hardening
- [x] known_good_hashes import (plain sha256/line + JSONL) + `psm enrich capture` OS-baseline command
- [x] VT hash-only lookup, opt-in (`--enrich vt`) — rate-limited, cached, size-capped
- [x] Schema validation + size/timeout audit — VT + ingest paths bounded
- [x] Fuzz macOS shim-JSON ingester (hypothesis, 5 strategies)
- [ ] (Stretch) `psm db export --signed` — deferred
- [x] **Exit check:** hostile shim JSON cannot crash the ingester; known-good hash on a planted unsigned exe suppresses the alert while the event still surfaces with a `known_good` label

## Phase 7 — Polish & Release
- [x] README + per-platform quickstart (README.md)
- [x] Threat model doc — controller self-inspection caveat included (docs/threat-model.md)
- [x] Permission setup guides (docs/setup/{windows,macos,android}.md)
- [x] Release tooling — wheel + shim + SHA256SUMS (tools/release.py + docs/release.md)
- [ ] pipx packaging verified on a clean Windows box — awaits fresh VM/user (docs/release.md §5)
- [x] Dogfooding checklist (docs/dogfood-checklist.md)
- [ ] One week dogfooding + fix top annoyances — awaits calendar time
- [ ] Tag v1.0 — gated on the two items above

## Backlog (Layer 2 — do NOT start before v1.0)
- [ ] osquery scheduled-query mode / ETW exploration (Windows)
- [ ] Sysmon event-log ingestion into the timeline
- [ ] Windows Filtering Platform flow events
- [ ] FSEvents continuous daemon (macOS shim v2)
- [ ] Android VPN-based network metadata
- [ ] HTTP proxy support (lab environments)
- [ ] Cross-scan correlation rules
- [ ] Timesketch direct integration
