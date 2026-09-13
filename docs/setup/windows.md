# Windows setup

The controller *is* the Windows box. Nothing to install on a remote — the
collector runs in-process.

## 1. Install

```powershell
# One-time: install pipx if you don't have it
python -m pip install --user pipx
python -m pipx ensurepath
# open a new PowerShell so PATH picks up %USERPROFILE%\.local\bin

# Install psm
pipx install psm-0.1.0-py3-none-any.whl
# ... or, from a checkout:
pipx install .

psm --version
```

If `psm` isn't on PATH after install, run `pipx ensurepath` again and reopen
PowerShell.

## 2. Register the device and run doctor

```powershell
psm device add --name this-pc --platform windows
psm doctor this-pc
```

`psm doctor` prints:

- Whether you're currently elevated.
- If not: what elevation would add (services, scheduled tasks, WMI subs,
  authenticode signing coverage on system paths, …).
- The file walk paths that will be hashed.

## 3. Elevation — do you need it?

**Non-elevated (default).** Covers everything a user can reach:

- HKCU Run keys and per-user Uninstall keys.
- User-writable file paths (`%USERPROFILE%`, `%APPDATA%`, `%LOCALAPPDATA%`).
- Chrome / Edge / Firefox extensions (all under the user profile).

This is the recommended default because most consumer malware plants itself in
user-writable locations.

**Elevated (Administrator).** Adds:

- HKLM Run keys, machine-wide Uninstall keys.
- Services, scheduled tasks, startup folder for All Users, WMI event
  subscriptions.
- Reading files under `C:\Program Files`, `C:\Windows` (authenticode on new /
  changed executables).

Right-click PowerShell → *Run as administrator* → `psm baseline this-pc` to
capture an elevated baseline. Subsequent non-elevated scans will note the
missing modules as **gaps**, not as removals — the diff engine only compares
modules present in both snapshots.

## 4. File walk paths

Default paths are chosen by `default_file_walk_paths()`. Override with:

```powershell
$env:PSM_FILE_WALK_PATHS = "C:\Users\me\Downloads;C:\Tools"
psm baseline this-pc
```

Multiple paths are separated by `;` on Windows. Each path is walked, hashed, and
size-capped (default cap enforced per-file to avoid pathological blowup).

## 5. Schedule the daily scan

```powershell
schtasks /Create /XML docs\samples\psm-daily.xml /TN "psm daily"
```

Edit `docs\samples\psm-daily.xml` first:

- `<UserId>` (implicit via `<Principal>`) — replace with your account SID or
  leave InteractiveToken to run only when you're logged in.
- `<StartBoundary>` — set to a real future date/time.
- `<Arguments>` — the default is `psm scan && psm report daily`. Exit code 3
  (alerts) will surface in Task Scheduler as a failed task; that's a feature.

Reports land in `%LOCALAPPDATA%\psm\reports\`.

## 6. Windows Defender / EDR

If your AV quarantines osquery-style enumeration you may see gaps in the
persistence or services modules. Add a `psm` exclusion for the pipx venv
directory only if you must — and prefer a per-executable exclusion over a
path-wide one. Never exclude `%APPDATA%` or user profile paths.

## 7. Troubleshooting

- **`psm` not on PATH after pipx install** — `pipx ensurepath`, reopen shell.
- **`psm doctor` says "not running on Windows"** — the CLI works cross-platform
  for reports and macOS ingest, but Windows collection needs to run on Windows.
- **All-zero events on first scan** — you scanned before baseline, or baseline
  captured everything the scan sees. `psm timeline --last 24h` will still be
  empty; that is correct.
- **osquery timeout** — increase your process budget; the collector caps at 300 s
  per subprocess with a 64 MB stdout cap. If you're regularly hitting this,
  narrow the file walk paths.
- **`psm db verify` reports "chain broken"** — do NOT scan again yet. Snapshot
  the DB file (`copy %LOCALAPPDATA%\psm\psm.sqlite psm-broken.sqlite`) before
  doing anything else so you have forensic material.
