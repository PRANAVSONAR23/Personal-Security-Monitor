# New file: {path}

- **Size:** {size} bytes
- **Modified:** {mtime}
- **Executable:** {executable}
- **Signature status:** {signature_status}
- **SHA-256:** `{sha256}`

## What this means

The file is new in a directory `psm` watches. Downloads, Desktop, and Roaming/AppData see
a lot of legitimate traffic — installers, temp files, browser downloads — but they're also
common landing spots for anything a user is tricked into running.

## Verification steps

1. If **executable** is `True` and **signature_status** is not `valid`, treat the file as
   unverified until you know where it came from.
2. Search the SHA-256 on VirusTotal (or run `psm scan --enrich vt` once enrichment is
   wired) before executing.
3. If you did not create this file, delete it and re-scan.
