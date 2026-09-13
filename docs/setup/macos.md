# macOS setup

psm on macOS is a **single-file stdlib shim** (`shim/psm_mac_collector.py`)
that runs on the Mac and emits one JSON envelope. The Windows controller
consumes envelopes over SSH (`psm scan mac --ssh user@host`) or from disk
(`psm ingest macos file.json --device mbp`).

No agent. No brew formula. No LaunchAgent installed for psm itself.

## Prerequisites on the Mac

- Python 3.10+ (Apple ships one, `python3` is enough).
- SSH server enabled if you want the controller to pull directly.
- Full Disk Access on the terminal that runs the shim, if you want TCC data.

## 1. Enable Remote Login (for SSH mode)

*System Settings → General → Sharing → Remote Login → On.*

Restrict "Allow access for" to a specific user rather than "All users". Take
note of the exact `user@host` — that's the SSH target you'll register.

Verify from the Windows controller:

```powershell
ssh user@mbp.local uname -sr
# Darwin 24.x.x
```

If the connection prompts for password every time and you'd rather use keys:

```powershell
ssh-keygen -t ed25519            # if you don't have a key yet
# copy the .pub to the Mac's ~/.ssh/authorized_keys:
Get-Content $env:USERPROFILE\.ssh\id_ed25519.pub | ssh user@mbp.local "cat >> ~/.ssh/authorized_keys"
```

## 2. Grant Full Disk Access

Without FDA the `permissions` module (TCC) records a gap; everything else still
works.

FDA has to be granted to **the process that opens `TCC.db`**, not to psm. In
SSH mode that process is `sshd` (or the login shell it spawns).

*System Settings → Privacy & Security → Full Disk Access* — enable for:

- **Terminal.app** — if you ever run the shim manually from Terminal.
- **sshd-keygen-wrapper** *or* **/usr/libexec/sshd-keygen-wrapper** — for SSH
  mode. On some macOS versions this shows up under a generic name; if you don't
  see it, drag `/usr/sbin/sshd` in explicitly with the `+` button.

You may need to add `/usr/bin/python3` explicitly on newer macOS if the shim
still reports a TCC gap after enabling sshd.

Reboot is not required, but you must **restart the SSH session** for the new
permission to take effect (macOS grants FDA per-process at spawn).

Verify:

```powershell
psm scan mbp --ssh user@mbp.local
# look at the scan report — a `permissions` gap with reason=fda-missing means
# the shim couldn't open TCC.db.
```

## 3. Register the device on the controller

```powershell
psm device add --name mbp --platform macos --identifier user@mbp.local
psm doctor mbp                        # checks the ssh binary and reachability
```

## 4. Baseline & scan

**SSH mode (streamed):**

```powershell
psm baseline mbp --ssh user@mbp.local
# ... time passes ...
psm scan     mbp --ssh user@mbp.local
```

**File-drop mode (offline / air-gapped):**

```bash
# on the Mac:
python3 shim/psm_mac_collector.py > baseline.json
python3 shim/psm_mac_collector.py > scan.json
```

```powershell
# on the controller:
psm ingest macos baseline.json --device mbp --kind baseline
psm ingest macos scan.json     --device mbp --kind scan
```

## 5. Shim options

```
python3 psm_mac_collector.py --modules apps,persistence,permissions,files,processes,network,browser
                             --file-walk /Users/me/Downloads:/opt/homebrew/bin
                             --max-file-mb 200
```

- `--modules` — comma list; drop modules you don't care about to speed things up.
- `--file-walk` — colon-separated paths (POSIX). Empty ⇒ no file-hash walk.
- `--max-file-mb` — per-file size cap. Files above this get an entry with
  no hash and a gap-style note.

Every module is guarded — one exception becomes one `gaps[]` entry, the envelope
still emits. Non-zero exit is reserved for argument errors, so the controller
can distinguish "shim broken" from "one module failed".

## 6. Troubleshooting

- **`ssh: connect: Connection refused`** — Remote Login isn't on, or a firewall
  is blocking. `sudo systemsetup -getremotelogin` on the Mac reports state.
- **`permissions: fda-missing`** in the scan report — sshd (or Terminal, in
  manual mode) doesn't have Full Disk Access. Re-check the FDA list and **kill
  the existing SSH session** so a fresh sshd child is spawned.
- **`network: lsof-not-found`** — `/usr/sbin/lsof` isn't on PATH for the SSH
  shell. Set `PATH` in the shim command or run through a login shell.
- **Envelope > 128 MB** — ingest rejects it with `ShimValidationError`. Narrow
  `--file-walk` or drop `files` module.
- **Timezone drift** — the shim writes `taken_at` in UTC. If your Mac's clock
  is wrong the hash chain still validates, but timeline windows will look off.
