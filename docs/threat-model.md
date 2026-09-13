# psm — Threat model

Scope: what psm is trying to notice, what an attacker would have to do to hide
from it, and where psm quietly loses. Read alongside `HLD.md` §D1–D10.

## Assumptions

1. The controller PC is trusted at the time of baseline. Everything past that is
   evaluated against the baseline.
2. The user runs `psm` interactively or via Task Scheduler under their own account,
   not as SYSTEM. Optional elevation adds coverage (see `elevation.py` /
   `docs/setup/windows.md`) but is not required.
3. Time on the controller is roughly correct — the hash chain records order, not
   absolute wall-clock trust.
4. The SQLite file (`%LOCALAPPDATA%\psm\psm.sqlite`) sits on user-writable storage.
   It is not protected against a user with admin rights on the same box —
   see "controller self-inspection caveat" below.

## What psm defends against

| Category | How it surfaces |
|---|---|
| A new persistence entry (Run key, LaunchAgent, `pm install`) | `persist:*` / `pkg:*` **added** event; correlates with unsigned binaries |
| A binary swapped in place | `file:*` **changed** event (sha256 diff), regardless of mtime tricks |
| A newly sideloaded / installer-mismatched Android app | `pkg:*` **added** with `installer=sideload` — built-in rule fires |
| A new runtime permission grant | `perm:<pkg>:<permission>` **added**; special-access grants fire an alert |
| A new browser extension with broad host permissions | `ext:*` **added** + `has_any: [<all_urls>, *://*/*]` rule fires |
| Tampering with the psm event history | `psm db verify` reports the first bad id |
| A rule missing a signal because the module wasn't collected | Every report surfaces the `gaps` list — no silent omissions |

## What psm does NOT defend against

1. **Memory-only malware.** psm is a snapshot tool — nothing survives that never
   touches disk, a registry hive, an installed permission, or a listening socket
   captured at snapshot time.
2. **Attacks between snapshots that revert before the next scan.** A file that
   flips → executes → flips back is invisible unless it left another trace
   (persistence entry, dropped file, permission grant).
3. **A determined attacker with admin on the controller.** They can rewrite the
   SQLite file, replace the `psm` wheel, or intercept the hash chain head. `psm
   db verify` catches history rewriting *of an existing chain*, but nothing
   protects against replacing the DB wholesale. Detached-signature export
   (`psm db export --signed`) is the mitigation and is deferred to v1.1.
4. **Attacks on the transports.** SSH auth is your responsibility. USB debugging
   over ADB implies the phone has authorized the controller — treat the
   controller's `~/.android/adbkey` accordingly.
5. **Kernel-mode rootkits.** psm reads user-mode inventory (registry, filesystem,
   `dumpsys`, `plist`). A rootkit that hides files from the OS also hides them
   from us.
6. **First-party supply-chain compromise of psm itself.** Pin your install,
   verify checksums (see `docs/release.md`), and don't `pip install` from a
   moving target.
7. **Zero-day exploits in the collectors we shell out to** (`osqueryi`,
   `adb.exe`, `codesign`, `lsof`). We pin osquery, cap subprocess output at
   64 MB, enforce timeouts, and JSON-parse — but the trust boundary is real.

## Controller self-inspection caveat

When psm runs on Windows and scans the same Windows box, the attacker's
compromised code and the psm database live on the same disk. Anything with SYSTEM
or Administrator rights can:

- Overwrite `%LOCALAPPDATA%\psm\psm.sqlite` with a synthetic clean baseline.
- Swap the `psm` shim / entry point with a stub that always says "clean".
- Prime a Windows Defender / EDR exclusion for the psm binary and then drop payloads inside its scan paths without triggering the *host* AV (psm still sees the changes on the next scan — but only if it wasn't neutered first).

**Mitigation:** point one PC at another PC (or Mac/phone) rather than the same
box wherever practical. Export the sqlite periodically to append-only media (a
USB stick you rotate offline, or a signed export in v1.1). If you do use psm as
same-box self-inspection, treat its output as *supplementary* signal, not
authoritative.

## Attacker cost model

A useful frame: what does an intrusion cost the attacker if psm is running?

| Attacker action | Cost added by psm |
|---|---|
| Drop a payload in `%APPDATA%` and register a Run key | One extra file event + one persistence event + likely an "unsigned + persistence correlated" alert. High enough to matter for consumer-grade malware. |
| Sideload an Android APK with accessibility grant | Two events (install + permission grant), both matched by shipped rules. |
| Install a malicious Chrome extension | One `ext:*` added event; if it wants `<all_urls>` it hits the built-in `has_any` rule. |
| Live only in memory, exfil via existing browser | Zero — psm won't see it. This is a genuine gap. |
| Replace an installer executable in place | One `file:*` changed event with a sha256 diff. |
| Compromise the psm sqlite | `psm db verify` breaks. Assumes attacker doesn't also replace the psm binary. |

## Threats to the hash chain

The chain is `row_hash = sha256(prev_row_hash || canonical_json(event_core))`
with `meta['chain_head']` tracking the head. It defends against:

- **Row edits in place** — recomputing the chain from genesis mismatches.
- **Row deletions from the middle** — the same recomputation fails.
- **Row insertions with forged prev-hashes** — you can only forge the tail because you don't have the genesis-forward context that would make the middle valid, unless you replay the whole DB (see next bullet).

It does NOT defend against:

- **Wholesale DB replacement.** Nothing in the DB knows what the "real" chain
  head *should* be from outside. Future work: `psm db export --signed` writes a
  detached minisign signature over the head, which a separate machine can
  verify.
- **A modification of the collectors that lies to psm's `store` layer.** Trust
  is bootstrapped from the running python binary.

## Rules-engine trust

Rules ship in `src/psm/rules/builtin/` and are loaded as YAML. There is no
sandbox — a malicious rule file could match on nothing and never alert. If you
enable third-party rules, review them the same way you'd review a lint plugin.

## Enrichment trust

- `known_good_hashes`: local table, entries carry `source` labels. If you import
  a compromised vendor manifest you'll suppress real alerts. Track your sources.
- VirusTotal: hash-only, opt-in. We never upload file content. A malicious VT
  response cannot execute code — worst case, it labels an event `vt:seen` when
  it shouldn't, which does not suppress alerts (only known-good does).

## What we owe the user

- No silent omissions. Every gap is recorded and appears in every report.
- Deterministic diffs. `diff(A, A) == ∅`.
- Reproducible hashes. Canonical JSON is a frozen spec (`LLD.md` §canonical JSON).
- No network by default. VT is a flag you set consciously.
