# PSM v2 — Aim

## What this is

A personal security monitoring tool for **two devices I own**: a MacBook Air (M5,
macOS 26) that acts as both controller and target, and a POCO M2 Pro (MIUI 14 /
Android 12) that is the primary target.

It answers three questions, and they are deliberately different questions:

| # | Question | Subsystem | Primitive |
|---|---|---|---|
| 1 | *What changed on this device?* | `inventory` | snapshot → diff → events |
| 2 | *Is anything on it bad?* | `hunt` | artifact → analyzers → findings |
| 3 | *What is it talking to?* | `flowlog` | continuous capture → flows |

v1 answered only #1. v2 answers all three. This is the reason for the rewrite:
#2 and #3 cannot be expressed as snapshot-diffs, and forcing them through
`diff()` would fight the model forever.

## Scope

**In scope — exactly two devices:**

- `mac` — this MacBook. Controller *and* monitored target. Collection is
  in-process; no transport layer.
- `phone` — the POCO M2 Pro, reached over **wireless ADB** (`adb pair` /
  `adb connect`). Non-rooted.

**Out of scope for v2:** Windows, iOS, any third device, multi-user operation,
remote/cloud anything, real-time blocking or prevention.

Windows was the v1 controller. It is deleted, not ported. If it ever comes back
it comes back as a target with its own collector.

## The three subsystems

### 1. `inventory` — "what changed?"

Ported from v1, which got this right. Capture a snapshot of device state
(applications, persistence, permissions, files, browser extensions), diff it
against the previous snapshot, emit events. Deterministic, pure, offline.

Answers: *I clicked something sketchy — what did it do?*

### 2. `hunt` — "is anything bad?"

New. Takes artifacts the inventory already knows about (files, APKs) and runs
analyzers over them: YARA rules, APK manifest and signer analysis, known-good
hash suppression, optional hash-only VirusTotal.

This is **not** an antivirus and does not pretend to be one. It is a set of
explainable, deterministic analyzers. Every finding names the analyzer that
produced it, the rule that matched, and the evidence. No opaque scoring.

Answers: *is this APK doing something it shouldn't?*

### 3. `flowlog` — "what is it talking to?"

New. Continuous capture of network flows off the phone, via two legs that cover
each other's blind spots:

- **Mac-as-router** — the phone runs on the Mac's Internet Sharing hotspot, so
  the Mac sees every packet with **zero footprint on the phone**. Yields DNS
  queries, TLS SNI hostnames (without breaking TLS), IPs, ports, timing, byte
  counts. Cannot tell you which app sent a flow.
- **On-device `VpnService`** — a local-only VPN app on the phone gets a TUN
  interface and per-UID attribution. No root required. Tells you *which app*.

Joined on `(timestamp, destination)`, the two legs give *"WhatsApp talked to
graph.facebook.com at 14:32"*. Either leg alone is a degraded but valid mode,
which matters because MIUI will kill the VPN service under memory pressure on a
4 GB device.

Answers: *which app is phoning home, and where?*

## Known limits — stated up front, not discovered later

These are properties of the platforms, not gaps to be closed later.

- **No TLS interception.** Ever, by default. Certificate pinning breaks, and it
  conflicts with the privacy-first stance. We collect metadata, DNS, and SNI.
- **Encrypted Client Hello** blinds SNI on sites that use it (increasingly common
  behind Cloudflare). Those flows degrade to IP + port only.
- **DNS-over-HTTPS** blinds the DNS leg. Android's Private DNS must be set to
  off/automatic for the router leg to see queries.
- **Per-tab browser attribution is impossible** from outside the browser. It
  requires a browser extension. Per-*app* attribution is achievable; per-tab is
  not, and v2 does not claim it.
- **Android memory / RAM inspection requires root.** On a POCO this means Mi
  Unlock: a mandatory waiting period, a full device wipe, and a tripped Play
  Integrity (banking apps, Google Wallet stop working). v2 is built entirely on
  the non-root path, with collectors declared root-aware so the extra modules
  slot in cleanly if that decision is ever made. Revisited at Phase 3.
- **macOS kernel telemetry is available** via `/usr/bin/eslogger` (104 ESF event
  types) with Full Disk Access + root, SIP left enabled. A real ESF system
  extension needs an Apple provisioning entitlement and is not pursued.

## Principles

- **Local-first.** Nothing leaves the Mac by default. VirusTotal is hash-only
  and opt-in per invocation.
- **Deterministic and explainable.** Same inputs, same outputs. Every alert and
  every finding can be traced to the rule that produced it.
- **Partial collection is normal.** Every gap is recorded and surfaced in every
  report. A module that returns nothing must say *why* — silent empty results
  are a bug, and were an actual bug in v1.
- **Forensic integrity where it means something.** The event log is
  hash-chained. The raw network firehose is not — chaining a million flows a day
  would make `db verify` useless and protects nothing worth protecting.
- **CLI-first. No daemon on the controller beyond the capture legs. No GUI.**
