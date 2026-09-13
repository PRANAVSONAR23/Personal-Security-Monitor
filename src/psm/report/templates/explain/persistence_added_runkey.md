# New autorun added under {hive}\\{key}

A new **Run key** entry named **{name}** was created.

- **Target:** `{target}`
- **Arguments:** `{args_joined}`

## What this means

Run keys tell Windows to launch a program every time you sign in. Legitimate installers add
them for auto-start components, but they're also the single most common persistence
mechanism used by unwanted software because they survive reboots and don't require admin
rights when written under HKCU.

## Verification steps

1. Open `regedit` and navigate to `{hive}\\{key}`.
2. Inspect the value **{name}** — the data field is the command Windows will run.
3. If the target is a program you did not intentionally install, delete the value and
   remove the underlying file; then re-run `psm scan` to confirm it stays gone.
