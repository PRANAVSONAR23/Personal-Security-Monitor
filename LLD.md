# PSM — Low-Level Design (LLD)

## 1. SQLite Schema

```sql
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE devices (
    id            INTEGER PRIMARY KEY,
    name          TEXT NOT NULL UNIQUE,
    platform      TEXT NOT NULL CHECK (platform IN ('windows','macos','android')),
    identifier    TEXT NOT NULL,            -- hostname / ssh target / adb serial
    created_at    TEXT NOT NULL,
    meta          TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE snapshots (
    id            INTEGER PRIMARY KEY,
    device_id     INTEGER NOT NULL REFERENCES devices(id),
    taken_at      TEXT NOT NULL,
    kind          TEXT NOT NULL CHECK (kind IN ('baseline','scan','before','after')),
    capabilities  TEXT NOT NULL,            -- JSON array of collected modules
    tool_version  TEXT NOT NULL,
    gaps          TEXT NOT NULL DEFAULT '[]' -- JSON array of collection_gap objects
);

-- content-addressed inventory payloads (deduped across snapshots)
CREATE TABLE items (
    hash          TEXT PRIMARY KEY,          -- sha256 of canonical_json(payload)
    category      TEXT NOT NULL,             -- file|application|permission|persistence|network|browser|process
    subject_key   TEXT NOT NULL,             -- stable identity, e.g. "file:C:\Tools\x.exe", "pkg:com.foo.app"
    payload       TEXT NOT NULL              -- canonical JSON
);
CREATE INDEX idx_items_subject ON items(category, subject_key);

CREATE TABLE snapshot_items (
    snapshot_id   INTEGER NOT NULL REFERENCES snapshots(id),
    item_hash     TEXT    NOT NULL REFERENCES items(hash),
    PRIMARY KEY (snapshot_id, item_hash)
);

CREATE TABLE events (
    id            INTEGER PRIMARY KEY,
    device_id     INTEGER NOT NULL REFERENCES devices(id),
    ts            TEXT NOT NULL,
    category      TEXT NOT NULL,
    action        TEXT NOT NULL,             -- added|removed|changed|observed
    subject_key   TEXT NOT NULL,
    before_hash   TEXT REFERENCES items(hash),
    after_hash    TEXT REFERENCES items(hash),
    snap_from     INTEGER REFERENCES snapshots(id),
    snap_to       INTEGER NOT NULL REFERENCES snapshots(id),
    severity      TEXT NOT NULL DEFAULT 'info'
                   CHECK (severity IN ('info','notice','warning','alert')),
    prev_row_hash TEXT NOT NULL,
    row_hash      TEXT NOT NULL UNIQUE       -- sha256(prev_row_hash || canonical_json(event_fields))
);
CREATE INDEX idx_events_device_ts ON events(device_id, ts);
CREATE INDEX idx_events_subject   ON events(subject_key);

CREATE TABLE alerts (
    id            INTEGER PRIMARY KEY,
    rule_id       TEXT NOT NULL,
    device_id     INTEGER NOT NULL REFERENCES devices(id),
    ts            TEXT NOT NULL,
    title         TEXT NOT NULL,
    detail        TEXT NOT NULL,             -- JSON: contributing event ids + rendered context
    status        TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','ack','closed'))
);

CREATE TABLE alert_events (
    alert_id  INTEGER NOT NULL REFERENCES alerts(id),
    event_id  INTEGER NOT NULL REFERENCES events(id),
    PRIMARY KEY (alert_id, event_id)
);

CREATE TABLE known_good_hashes (
    sha256   TEXT PRIMARY KEY,
    source   TEXT NOT NULL,                  -- 'nsrl'|'user'|'os-baseline'
    label    TEXT
);

CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);  -- schema_version, chain_head, etc.
```

### Canonical JSON
`canonical_json(x)`: UTF-8, sorted keys, no whitespace, floats forbidden (stringify). Used for item hashing and the event chain — must never change once released; version it in `meta.schema_version`. Windows paths are normalized to lowercase drive letter + backslashes before hashing so casing differences don't create phantom changes.

### Subject key conventions
```
file:<abs-path>                       (file:C:\Users\x\Downloads\a.exe, file:/usr/local/bin/x)
pkg:<bundle-or-package-id>            (Microsoft.WindowsTerminal, com.apple.Safari, com.whatsapp)
persist:<platform>:<location>:<name>  (persist:windows:runkey:HKCU\...\Run\Foo,
                                       persist:macos:launchagent:com.foo.bar)
perm:<pkg>:<permission>
net:listen:<proto>:<port>:<process>
ext:<browser>:<extension-id>
proc:<path>                           (observed processes)
```

## 2. Canonical Item Payloads (per category)

```jsonc
// application
{ "id": "Microsoft.WindowsTerminal", "name": "Windows Terminal", "version": "1.20",
  "path": "C:\\Program Files\\WindowsApps\\…", "installed_at": "2026-07-01T10:00:00Z",
  "signer": "CN=Microsoft Corporation", "signature_status": "valid|invalid|unsigned|notarized",
  "source": "store|msi|exe|brew|appstore|pkg|sideload|unknown" }

// file
{ "path": "C:\\Users\\x\\AppData\\Roaming\\bar.exe", "sha256": "…", "size": 812,
  "mtime": "…", "attrs": "archive", "owner": "x", "executable": true,
  "signature_status": "unsigned" }

// persistence (windows run key)
{ "location": "runkey", "hive": "HKCU", "key": "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
  "name": "Foo", "target": "C:\\Users\\x\\AppData\\Roaming\\bar.exe", "args": ["-d"], "enabled": true }

// persistence (macos launch agent)
{ "location": "launchagent", "name": "com.bar", "target": "/usr/local/bin/bar",
  "args": ["-d"], "enabled": true, "run_at_load": true }

// permission (android)
{ "pkg": "com.whatsapp", "permission": "android.permission.CAMERA",
  "granted": true, "flags": ["user-set"] }

// special access (android, modeled as permission category)
{ "pkg": "com.foo", "permission": "special:accessibility", "granted": true }

// permission (macos TCC)
{ "pkg": "com.foo.app", "permission": "kTCCServiceCamera", "granted": true }

// network (listening socket)
{ "proto": "tcp", "port": 8080, "addr": "0.0.0.0", "process": "C:\\Tools\\bar.exe", "pid_seen": 4242 }

// browser extension
{ "browser": "chrome", "id": "abcdef…", "name": "Foo Ext", "version": "1.2",
  "permissions": ["tabs","<all_urls>"], "install_time": "…" }
```

## 3. Collector Interface

```python
class Collector(ABC):
    platform: str
    ALL_MODULES: tuple[str, ...]

    @abstractmethod
    def capabilities(self, device: Device) -> set[str]: ...
    @abstractmethod
    def collect(self, device: Device, modules: set[str],
                timeout_s: int = 300) -> RawBundle: ...

@dataclass
class RawBundle:
    device: Device
    taken_at: datetime
    raw: dict[str, bytes | str]      # module name -> raw output
    gaps: list[CollectionGap]        # module, reason, detail

class Normalizer(ABC):
    @abstractmethod
    def normalize(self, bundle: RawBundle) -> list[InventoryItem]: ...
```

### Windows module mechanisms (v1, local in-process)
| module | mechanism |
|---|---|
| apps | osquery `programs`; `Get-AppxPackage` for store apps |
| persistence | osquery `registry` (Run/RunOnce for HKLM+HKCU), `services`, `scheduled_tasks`, `startup_items`; WMI `__EventFilter`/`CommandLineEventConsumer` via osquery `wmi_*` tables |
| permissions | Appx capabilities (limited); recorded as partial capability |
| files | hash-walk configured path set (default: Downloads, %APPDATA%, %LOCALAPPDATA%\Temp exclusions applied, %USERPROFILE%\Desktop, C:\Tools) with size cap 200 MB, skip re-hash when (size, mtime, file_id) unchanged |
| signatures | osquery `authenticode` on new/changed executables only |
| network | osquery `listening_ports` + `process_open_sockets` snapshot (metadata only) |
| browser | copy-then-read Chrome/Edge/Firefox profile files (extensions, downloads) |
| processes | osquery `processes` |

Elevation: run elevated for full HKLM/services/tasks coverage; unelevated runs record `collection_gap("persistence", "not-elevated")` for the affected hives.

### macOS shim (v1, remote)
Single file `psm_mac_collector.py`, **stdlib-only**, compatible with macOS system Python3 (or bundled via `python3` from CLT). Invocation modes:
- SSH: `psm scan mac --ssh user@host` → controller runs `ssh user@host 'python3 -' < psm_mac_collector.py --modules …` and reads JSON from stdout. Uses macOS built-in Remote Login; controller never listens.
- Manual: user runs the shim on the Mac, gets `psm-mac-<host>-<ts>.json`, transfers it, `psm ingest macos FILE`.

| module | mechanism (runs on the Mac) |
|---|---|
| apps | walk /Applications + ~/Applications; `system_profiler SPApplicationsDataType -json` |
| persistence | plistlib over LaunchAgents/LaunchDaemons dirs, `launchctl list`, login items, `crontab -l`, `profiles list` |
| permissions | copy-then-read TCC.db (system + user) — requires FDA for the invoking process |
| files | hash-walk (~/Downloads, ~/Library/LaunchAgents, /usr/local/bin, /opt/homebrew/bin), same skip-cache rules |
| signatures | `codesign -dv --verbose=2`, `spctl -a -vv` on new/changed executables — must run on the Mac; results shipped as data |
| network | `lsof -i -nP` snapshot |
| browser | copy-then-read Chrome/Safari/Firefox profile stores |
| processes | `ps axo pid,ppid,uid,lstart,command` |

Shim output schema = same envelope as any RawBundle:
```json
{ "psm_collector": "macos", "version": "1.0", "host": "…", "taken_at": "…",
  "modules": { "apps": [...], "persistence": [...], ... }, "gaps": [...] }
```

### Android module commands (v1, non-root, adb.exe from the PC)
| module | mechanism |
|---|---|
| packages | `pm list packages -f -i --show-versioncode`; `dumpsys package <pkg>` (version-keyed parser) |
| permissions | `dumpsys package` grants section |
| special_access | `settings get secure enabled_accessibility_services`; `dpm list-owners`; `dumpsys device_policy` |
| downloads | `ls -l` on /sdcard/Download + content query where permitted |
| processes | `ps -A` (limited visibility) |
| netstats | `dumpsys netstats` per-uid summary |

`psm doctor` additionally detects `unauthorized`/`offline` ADB states (common on Windows when the OEM USB driver is missing) and prints driver guidance.

## 4. Diff Algorithm

```
diff(snapA, snapB):
    shared = capabilities(A) ∩ capabilities(B)
    for category in shared:
        A_map = {subject_key: item_hash} from snapshot_items(A, category)
        B_map = same for B
        added   = B_map.keys - A_map.keys      → Event(action=added,  after=B)
        removed = A_map.keys - B_map.keys      → Event(action=removed, before=A)
        changed = keys where hash differs      → Event(action=changed, before=A, after=B)
                  + attribute-level delta computed lazily for display
    modules only in one snapshot → collection-scope note, NOT events
```
Pure function; unit-tested with golden snapshot pairs.

## 5. Rules Engine

Rules are YAML, evaluated over the event batch of one diff:

```yaml
- id: unsigned-binary-user-path
  severity: alert
  title: "New unsigned executable in user-writable location"
  match:
    category: file
    action: added
    where:
      payload.executable: true
      payload.signature_status: ["unsigned", "invalid"]
      payload.path: { prefix_any: ["C:\\Users\\", "/Users/", "/usr/local/", "/opt/homebrew/"] }

- id: persistence-plus-new-file
  severity: alert
  title: "New persistence entry targets a file created in the same scan"
  correlate:
    a: { category: persistence, action: added }
    b: { category: file, action: added }
    join: a.payload.target == b.payload.path
```

Engine: filter-match per rule (`match`) and pairwise join (`correlate`) within a single event batch only (no cross-scan correlation in v1). Path comparisons use the same normalization as subject keys, so Windows casing never breaks a join.

## 6. Hash Chain

```
head = meta['chain_head'] or GENESIS
for each event insert (single transaction, ordered):
    row_hash = sha256(head + canonical_json(event_core_fields))
    event.prev_row_hash, event.row_hash = head, row_hash
    head = row_hash
meta['chain_head'] = head
```
`psm db verify` recomputes from genesis; O(n), acceptable for personal volumes.

## 7. CLI Specification

```
psm device add [--platform windows|macos|android] [--name NAME] [--ssh user@host]
psm device list
psm doctor [DEVICE]                # checks elevation, adb+drivers, ssh reachability, Mac FDA
psm baseline [DEVICE]
psm scan [DEVICE] [--against baseline|last] [--modules m1,m2] [--json] [--enrich vt]
         [--ssh user@host]         # macOS remote collection
psm watch --before-after [DEVICE]  # snapshot, wait for keypress, snapshot, diff
psm ingest macos FILE              # manual shim-output ingestion
psm persistence [DEVICE] [--diff]
psm timeline [--device D] [--last 7d] [--category c] [--export jsonl PATH]
psm report daily [--out DIR]
psm explain EVENT_ID
psm alerts [--open|--ack ID|--close ID]
psm db verify | vacuum | export [--signed]
```

Exit codes: 0 clean, 1 error, 2 scan completed with warnings, 3 scan produced alerts (scriptable — usable from Task Scheduler).

## 8. Explain Templates

Per (category, action) pair, a template with slot-filled payload values + static context, e.g. persistence/added (runkey) → what Run keys are, why an entry in HKCU pointing at %APPDATA% matters, suggested verification steps. Stored as markdown files in `explain/`, selectable by locale later.

## 9. Configuration (`config.yaml` in %LOCALAPPDATA%\psm\)

```yaml
paths:
  windows_hash_walk: ["%USERPROFILE%\\Downloads", "%APPDATA%", "%USERPROFILE%\\Desktop"]
  macos_hash_walk: ["~/Downloads", "~/Library/LaunchAgents", "/usr/local/bin", "/opt/homebrew/bin"]
  max_file_size_mb: 200
scan:
  timeout_s: 300
ssh:
  mac_target: "pranav@macbook.local"    # default for `psm scan mac`
enrich:
  vt_api_key: null          # hash-only lookups, opt-in per run
report:
  out_dir: "%LOCALAPPDATA%\\psm\\reports"
```

## 10. Testing Strategy

- Golden-file tests per normalizer: recorded raw output (osquery rows, dumpsys per Android version, shim JSON) → expected items.
- Property test on diff: diff(A,A) == ∅; diff symmetry of added/removed.
- Chain test: mutate any event row → verify fails.
- Shim contract test: `psm_mac_collector.py` output validates against `collector.schema.json` on every CI run (macOS runner).
- End-to-end on Windows in CI (self-scan of a fixture directory tree).
