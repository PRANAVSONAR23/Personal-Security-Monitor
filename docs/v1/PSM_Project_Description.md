# Personal Security Monitor (PSM)

## Vision

A personal, cross-platform forensic monitoring system controlled from a Windows PC that inspects Windows, macOS, and Android devices. PSM answers the question *"What changed on my device?"* rather than *"Is this malware?"* — emphasizing system-behavior transparency over signature detection.

PSM is **not an antivirus**. It is a lightweight personal EDR / host-monitoring and forensic-inspection tool.

## Core Model: Baseline → Snapshot → Diff → Events

The primary primitive in v1 is **snapshot-diffing**, not continuous daemons:

1. `psm baseline` — capture a full known-good snapshot of a device.
2. `psm scan` — capture a new snapshot, diff against the baseline, emit standardized events.
3. `psm watch --before-after` — snapshot, let the user perform a risky action (open a file, click a link), snapshot again, show the exact delta.

Continuous monitoring (osquery scheduled queries, ETW, FSEvents) is deferred to Layer 2. Snapshot-diff is simpler, identical across all platforms, and matches the real use case.

## High-Level Architecture

```text
                     Windows PC (Controller)
   ┌──────────────────────────────────────────────────┐
   │  CLI • SQLite • Diff Engine • Timeline • Reports │
   │  Correlation Rules • Baseline Store • Config     │
   └───────────────┬──────────────────────────────────┘
                   │  standardized JSON events
     ┌─────────────┼─────────────────┐
     │             │                 │
 Windows Collector │            macOS Collector
 (native, in-      │            (remote shim: SSH
  process: osquery │             or JSON file)
  + WMI/registry)  │                 │
     │       Android Collector       │
     │       (USB + ADB, agentless)  │
     │             │                 │
     └─────────────┴─────────────────┘
        Collect → Normalize → Store → Diff → Report
```

## Responsibilities

### Controller (Windows)
- CLI (single entry point: `psm`)
- SQLite database (devices, snapshots, events, alerts)
- Snapshot diff engine
- Timeline generation and export (JSONL / Timesketch-compatible)
- Correlation rules (e.g., *new unsigned binary + new Run-key entry*)
- Hash enrichment (local known-good set; optional hash-only VirusTotal lookup, opt-in)
- Report generation (daily change reports, scan reports)
- Configuration and baseline management

### Collectors

#### Windows (local, in-process)
Native collection on the controller itself via a pinned **osquery** binary plus direct APIs: programs, services, Run/RunOnce keys, scheduled tasks, startup folders, WMI event subscriptions, listening ports, processes, Authenticode signature status, and a hash walk of high-signal directories. No handoff files — collection runs inside the controller.

#### macOS (remote shim)
A small self-contained collector script runs on the Mac and returns standardized JSON: application inventory, launchd persistence, TCC permissions (needs Full Disk Access on the Mac), `codesign`/notarization checks (must execute on the Mac), browser profiles, `lsof` network snapshot, process list. Invoked over SSH (`psm scan mac --ssh user@mac`, using macOS's built-in Remote Login) or by copying the JSON output (`psm ingest macos FILE`). No permanent agent.

#### Android
Agentless via USB + ADB from the Windows PC. Realistic non-root scope: package inventory, versions, install/update times, per-app permissions, device-admin and accessibility-service grants, shared-storage downloads, partial process list, network stats. OEM USB drivers may be required on Windows; `psm doctor` checks for a working ADB connection. No permanent background agent in v1.

## Event Model

Everything is a standardized event with: device, timestamp, category, action, subject, attributes, source snapshot pair.

Categories:
- File (created / deleted / modified / hash-changed)
- Application (installed / removed / updated)
- Process (observed / new-listener)
- Permission (granted / revoked / changed)
- Persistence (autostart added / removed / modified)
- Network (new connection / new listening port / DNS observation)
- Browser (extension added/removed, download, settings change)

## Persistence-First Detection

A dedicated `psm persistence` command dumps and diffs every autostart location:
- Windows: Run/RunOnce keys, services, scheduled tasks, startup folders, WMI subscriptions
- macOS: LaunchAgents, LaunchDaemons, login items, configuration profiles, cron, system extensions
- Android: device-admin apps, accessibility services, default-app changes

## SQLite Tables

devices, snapshots, snapshot_items, events, files, applications, permissions, persistence_entries, downloads, network_observations, browser_extensions, alerts, event_hash_chain

The events table is **hash-chained** for tamper evidence.

## Layer 1 (Core)
- Baseline / scan / before-after snapshot diffing
- Persistence monitoring
- Application and permission inventory diffing
- Browser extension and download monitoring
- Network metadata snapshots (connections, listeners, DNS cache where readable)
- Code-signature status of new executables (Authenticode locally; codesign via the Mac shim)
- Timeline + `psm explain <event-id>` plain-language context
- Daily change reports (Task Scheduler)
- CLI + SQLite + tamper-evident event log

## Layer 2 (Research)
- Continuous monitoring: osquery scheduled queries / ETW (Windows), FSEvents daemon (macOS shim)
- Windows Filtering Platform flow events
- Sysmon integration (ingest Sysmon event logs into the timeline)
- Android VPN-based network metadata
- HTTP proxy support for controlled environments
- TLS interception: explicitly out of scope by default (pinning breakage, privacy-first conflict); documented lab-only appendix at most

## HTTPS Limitation

Universal inspection of HTTPS URLs/payloads is not generally possible (TLS, certificate pinning, OS protections). PSM focuses on **network metadata**: endpoints, ports, DNS, listening sockets, per-app network attribution where available.

## Design Principles
- The Windows PC is the single control point.
- Snapshot-diff first; daemons later.
- Platform-specific collectors, platform-independent event model.
- Local-first. No cloud. Optional enrichment is opt-in and hash-only.
- No AI dependency.
- Privacy-first. CLI-first.
- Forensic integrity: append-only, hash-chained event log.
