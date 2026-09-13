# psm — Personal Security Monitor

A local, deterministic forensic snapshot-diff tool for **Windows, macOS, and Android**.
No daemons. No cloud. No agents on the endpoints beyond a single-file stdlib shim
(macOS) or `adb`-driven collection (Android). The Windows PC is the controller.

Every run answers one question: *what changed on this device since last time, and
does it match a known-bad pattern?*

- **Collect → Normalize → Store → Diff → Report** on demand.
- SQLite with a SHA-256 hash chain — `psm db verify` proves nothing was rewritten.
- Rule-based alerts, YAML-defined, purely local.
- VirusTotal enrichment is **hash-only** and strictly opt-in.

Not an antivirus. Not a continuous EDR. Not a GUI.

---

## Install

Requires Python 3.12+.

```powershell
# From a source checkout on the controller (Windows):
pipx install .

# Or, from a release wheel:
pipx install psm-0.1.0-py3-none-any.whl
```

`pipx` gives you an isolated venv with the `psm` entry point on `PATH`.

---

## First run — Windows self-inspection

```powershell
psm device add --name this-pc --platform windows
psm doctor this-pc
psm baseline this-pc
# ... time passes, something changes ...
psm scan this-pc
```

Exit codes: **0** clean · **1** error · **2** warnings (collection gaps) · **3** alerts.

The scan report lists every added/changed/removed item and the rule that matched.
Use `psm explain <event-id>` for the "why does this matter" write-up.

## macOS — SSH mode

You keep the Windows PC as the controller and the shim streams over SSH.

```powershell
psm device add --name mbp --platform macos --identifier user@mbp.local
psm doctor mbp                          # checks ssh binary is reachable
psm baseline mbp --ssh user@mbp.local
psm scan     mbp --ssh user@mbp.local
```

Or run the shim by hand on the Mac and ingest the file:

```bash
python3 shim/psm_mac_collector.py > baseline.json
# copy baseline.json to the Windows PC, then:
psm ingest macos baseline.json --device mbp --kind baseline
```

See [`docs/setup/macos.md`](docs/setup/macos.md) for Full Disk Access + Remote Login setup.

## Android — ADB mode

```powershell
psm device add --name pixel --platform android --identifier <serial>
psm doctor pixel                        # verifies adb, USB auth, driver hints
psm baseline pixel
psm scan pixel
```

See [`docs/setup/android.md`](docs/setup/android.md) for USB debugging + OEM driver setup.

---

## What surfaces as an event

| Platform | Modules |
|---|---|
| Windows | persistence (Run keys), apps (Uninstall keys), files (hash walk), browser (Chrome/Edge/Firefox extensions) |
| macOS   | apps, LaunchAgents/Daemons, TCC permissions, files, processes, network (listening), browser extensions |
| Android | packages (installer classification), runtime permissions, special access (accessibility, device-admin) |

Each item has a stable **subject key** (`file:<path>`, `pkg:<id>`, `persist:<platform>:<location>:<name>`, …).
Diffs are per-subject: `added`, `removed`, or `changed`.

## Enrichment

```powershell
# Import a known-good hash list (one sha256/line, or JSONL {sha256, source, label}):
psm enrich import my-baseline.txt --source vendor-manifest

# Snapshot your current file inventory as known-good:
psm enrich capture --device this-pc --source clean-image

# Suppress alerts whose only file-hits are on known-good hashes:
psm scan this-pc --enrich known_good

# Add VirusTotal (hash-only lookups; needs PSM_VT_API_KEY):
$env:PSM_VT_API_KEY = "..."
psm scan this-pc --enrich known_good,vt
```

Suppressed events still appear in the scan report — labeled `known_good` or
`vt:malicious(N)` — the alert row is what gets filtered.

## Reports & timeline

```powershell
psm timeline --device this-pc --last 7d --category file
psm timeline --last 24h --export events.jsonl        # Timesketch-compatible
psm report daily --last 24h                           # writes Markdown to %LOCALAPPDATA%\psm\reports
```

Schedule the daily report via `docs/samples/psm-daily.xml`
(`schtasks /Create /XML docs\samples\psm-daily.xml /TN "psm daily"`).

## Hash chain

Every event row participates in a SHA-256 chain:

```
row_hash = sha256(prev_row_hash || canonical_json(event_core))
```

`psm db verify` walks the chain from genesis. A tampered event surfaces as the
first bad id.

## Design docs

- [`architecture.md`](architecture.md) — narrative overview
- [`HLD.md`](HLD.md) — module map, 10 design decisions, error philosophy
- [`LLD.md`](LLD.md) — schema, canonical JSON spec, diff algorithm, hash chain, rules
- [`implementation.md`](implementation.md) — layout, stack, conventions
- [`docs/threat-model.md`](docs/threat-model.md) — what psm defends against, what it doesn't
- [`plan.md`](plan.md) — the 7 phases; [`todo.md`](todo.md) tracks progress

## License

MIT.
