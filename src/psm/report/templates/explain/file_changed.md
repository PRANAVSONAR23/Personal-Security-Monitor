# File changed: {path}

- **New SHA-256:** `{sha256}`
- **New size:** {size} bytes
- **Modified:** {mtime}

## What this means

The file at this path was replaced or edited since the previous snapshot. For executables
in system paths this is worth attention — legitimate binaries rarely change outside of an
update event. For documents or logs, changes are usually expected.

## Verification steps

1. If the file is an executable, confirm you ran an update that would touch it.
2. Compare the new SHA-256 against known-good sources if available.
