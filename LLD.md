# PSM v2 — Low-Level Design

## 1. Schema

Ported tables keep their v1 shape where it was right. New tables carry the two
new subsystems.

### 1.1 Shared (ported from v1)

```sql
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE devices (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,            -- 'mac' | 'phone'
    platform    TEXT NOT NULL CHECK (platform IN ('macos','android')),
    identifier  TEXT NOT NULL,                   -- 'local' | adb serial / host:port
    tiers       TEXT NOT NULL DEFAULT '[]',      -- JSON: satisfied tiers at last doctor
    created_at  TEXT NOT NULL,
    meta        TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE snapshots (
    id           INTEGER PRIMARY KEY,
    device_id    INTEGER NOT NULL REFERENCES devices(id),
    taken_at     TEXT NOT NULL,
    kind         TEXT NOT NULL CHECK (kind IN ('baseline','scan','before','after')),
    capabilities TEXT NOT NULL,                  -- JSON array, DERIVED from collection
    tool_version TEXT NOT NULL,
    gaps         TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE items (                             -- content-addressed, deduped
    hash        TEXT PRIMARY KEY,
    category    TEXT NOT NULL,
    subject_key TEXT NOT NULL,
    payload     TEXT NOT NULL
);
CREATE INDEX idx_items_subject ON items(category, subject_key);

CREATE TABLE snapshot_items (
    snapshot_id INTEGER NOT NULL REFERENCES snapshots(id),
    item_hash   TEXT    NOT NULL REFERENCES items(hash),
    PRIMARY KEY (snapshot_id, item_hash)
);

CREATE TABLE events (                            -- CHAINED. conclusions only.
    id            INTEGER PRIMARY KEY,
    device_id     INTEGER NOT NULL REFERENCES devices(id),
    ts            TEXT NOT NULL,
    source        TEXT NOT NULL                  -- NEW: which subsystem produced it
                    CHECK (source IN ('inventory','hunt','flowlog','esf')),
    category      TEXT NOT NULL,
    action        TEXT NOT NULL,
    subject_key   TEXT NOT NULL,
    before_hash   TEXT REFERENCES items(hash),
    after_hash    TEXT REFERENCES items(hash),
    snap_from     INTEGER REFERENCES snapshots(id),
    snap_to       INTEGER REFERENCES snapshots(id),
    ref_id        INTEGER,                       -- NEW: finding.id / flow rollup id
    severity      TEXT NOT NULL DEFAULT 'info'
                    CHECK (severity IN ('info','notice','warning','alert')),
    prev_row_hash TEXT NOT NULL,
    row_hash      TEXT NOT NULL UNIQUE
);
CREATE INDEX idx_events_device_ts ON events(device_id, ts);
CREATE INDEX idx_events_source    ON events(source, ts);

CREATE TABLE alerts (
    id        INTEGER PRIMARY KEY,
    rule_id   TEXT NOT NULL,
    device_id INTEGER NOT NULL REFERENCES devices(id),
    ts        TEXT NOT NULL,
    title     TEXT NOT NULL,
    detail    TEXT NOT NULL,
    status    TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','ack','closed'))
);
CREATE TABLE alert_events (
    alert_id INTEGER NOT NULL REFERENCES alerts(id),
    event_id INTEGER NOT NULL REFERENCES events(id),
    PRIMARY KEY (alert_id, event_id)
);

CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
```

`snap_to` becomes nullable: hunt and flowlog events have no snapshot pair.

### 1.2 Hunt (new)

```sql
CREATE TABLE artifacts (                         -- a thing that can be analyzed
    id          INTEGER PRIMARY KEY,
    device_id   INTEGER NOT NULL REFERENCES devices(id),
    kind        TEXT NOT NULL CHECK (kind IN ('file','apk','dylib','script')),
    subject_key TEXT NOT NULL,                   -- file:/path  |  pkg:com.foo
    sha256      TEXT,                            -- NULL when oversize/unreadable
    size        INTEGER,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    local_path  TEXT,                            -- staging path for pulled APKs
    UNIQUE (device_id, subject_key)
);
CREATE INDEX idx_artifacts_sha ON artifacts(sha256);

CREATE TABLE findings (                          -- NOT chained: re-evaluable
    id               INTEGER PRIMARY KEY,
    artifact_id      INTEGER NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    analyzer_id      TEXT NOT NULL,              -- 'yara' | 'apk_signer' | 'vt' | ...
    analyzer_version TEXT NOT NULL,
    rule_id          TEXT,                       -- YARA rule / heuristic id
    verdict          TEXT NOT NULL
                       CHECK (verdict IN ('clean','suspicious','malicious','unknown')),
    confidence       TEXT NOT NULL DEFAULT 'medium'
                       CHECK (confidence IN ('low','medium','high')),
    evidence         TEXT NOT NULL DEFAULT '{}', -- JSON: what matched, where
    ts               TEXT NOT NULL,
    UNIQUE (artifact_id, analyzer_id, analyzer_version, rule_id)
);
CREATE INDEX idx_findings_verdict ON findings(verdict, ts);

CREATE TABLE known_good_hashes (
    sha256 TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    label  TEXT
);
```

The `UNIQUE` on findings is what makes re-running idempotent: the same analyzer
at the same version on the same artifact upserts rather than duplicating.

### 1.3 Flowlog (new)

```sql
CREATE TABLE flows (                             -- raw. high volume. retention-capped.
    id         INTEGER PRIMARY KEY,
    device_id  INTEGER NOT NULL REFERENCES devices(id),
    ts         TEXT NOT NULL,
    leg        TEXT NOT NULL CHECK (leg IN ('router','device')),
    proto      TEXT NOT NULL,
    src_port   INTEGER,
    dst_ip     TEXT NOT NULL,
    dst_port   INTEGER NOT NULL,
    hostname   TEXT,                             -- from DNS or TLS SNI (router leg)
    sni_status TEXT CHECK (sni_status IN ('plain','ech','none')),
    app_uid    INTEGER,                          -- device leg only
    app_pkg    TEXT,                             -- device leg only
    bytes_out  INTEGER NOT NULL DEFAULT 0,
    bytes_in   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_flows_ts   ON flows(device_id, ts);
CREATE INDEX idx_flows_dst  ON flows(dst_ip, ts);
CREATE INDEX idx_flows_host ON flows(hostname);

CREATE TABLE flow_rollups (                      -- what reports actually query
    id          INTEGER PRIMARY KEY,
    device_id   INTEGER NOT NULL REFERENCES devices(id),
    hour        TEXT NOT NULL,                   -- 'YYYY-MM-DDTHH'
    app_pkg     TEXT,                            -- NULL = unattributed
    hostname    TEXT,
    dst_ip      TEXT,
    dst_port    INTEGER,
    flow_count  INTEGER NOT NULL,
    bytes_out   INTEGER NOT NULL,
    bytes_in    INTEGER NOT NULL,
    first_ts    TEXT NOT NULL,
    last_ts     TEXT NOT NULL,
    UNIQUE (device_id, hour, app_pkg, hostname, dst_ip, dst_port)
);
CREATE INDEX idx_rollup_app  ON flow_rollups(app_pkg, hour);
CREATE INDEX idx_rollup_host ON flow_rollups(hostname, hour);
```

Retention: raw `flows` kept 7 days by default, then dropped after rollup.
`flow_rollups` kept indefinitely — they're small.

## 2. Canonical JSON — frozen, with one corrected freeze

Unchanged from v1: UTF-8, sorted keys, no whitespace, floats forbidden.

```python
def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
```

**Changed — `norm_path` becomes platform-aware.** v1 casefolded every path as a
Windows path, including on case-sensitive filesystems, which silently conflated
`/Users/Pranav/x` with `/users/pranav/x` in rule predicates and joins.

```python
def norm_path(p: str, platform: Platform) -> str:
    if platform == "windows":                # retained for future Windows target
        p = p.replace("/", "\\")
        if len(p) >= 2 and p[1] == ":":
            p = p[0].upper() + p[1:]
        return p.casefold()
    if platform == "macos":                  # APFS default is case-INsensitive
        return unicodedata.normalize("NFC", p).casefold()
    return unicodedata.normalize("NFC", p)   # android: case-sensitive, no fold
```

macOS keeps the casefold (APFS is case-insensitive by default) but gains NFC
normalization — macOS hands out NFD filenames and unnormalized comparison
produces phantom diffs on any accented filename. Android is case-sensitive and
must not fold.

This is a v2.0 spec. `meta.canonical_json_version = 2`.

## 3. Subject keys

```text
file:<abs-path>                         file:/Users/x/Downloads/a.dmg
pkg:<bundle-or-package-id>              pkg:com.whatsapp, pkg:com.apple.Safari
proc:<path>
net:listen:<proto>:<port>:<process>
flow:<app-or-uid>:<hostname-or-ip>      flow:com.whatsapp:graph.facebook.com
find:<analyzer>:<subject-key>           find:yara:file:/Users/x/a.dmg

persistence
  macos launchd   persist:macos:<location>:<scope>:<name>
                  persist:macos:launchagent:user:com.foo
  macos BTM       persist:macos:loginitem:<uid>:<uuid>
  android         persist:android:<location>:<name>

permission
  macos TCC       perm:<scope>:<client>:<service>[:<target>]
                  perm:user:com.desktime.DeskTime:kTCCServiceAppleEvents:com.google.Chrome
  android         perm:<pkg>:<permission>

browser           ext:<browser>:<profile>:<extension-id>
                  ext:chrome:Default:elicpjhcidhpjomhibiffojpinpmmpil
```

Three of these are wider than the v1 spec, because v1's shapes were not unique:

- **macOS permissions carry scope and target.** TCC's own primary key is
  `(service, client, client_type, indirect_object_identifier)`. On the
  development Mac, `perm:<pkg>:<permission>` collided immediately: DeskTime holds
  two distinct AppleEvents grants, one to drive Brave and one to drive Chrome.
  Dropping the target silently merges them and one overwrites the other.
- **macOS persistence carries scope**, so an Apple-shipped
  `/System/Library` job and a user LaunchAgent with the same label stay distinct,
  and reports can separate "Apple shipped this" from "something installed this
  into my account".
- **Browser extensions carry the profile.** The same extension installed in two
  Chrome profiles is two installs with independently grantable permissions.

Android keeps `perm:<pkg>:<permission>`: there, that pair genuinely is the
identity.

## 4. Interfaces

```python
# ---- poll: Adapter ----
class Collector(ABC):
    platform: str
    ALL_MODULES: tuple[str, ...]
    def satisfied_tiers(self, device: Device) -> set[str]: ...
    def capabilities(self, device: Device) -> set[str]: ...
    def collect(self, device: Device, modules: set[str]) -> RawBundle: ...

@dataclass
class RawBundle:
    device: Device
    taken_at: str
    raw: dict[str, list[dict]]       # category -> entries
    gaps: list[CollectionGap]
    collected: set[str]              # NEW: what actually produced output (D6)

# ---- stream: Producer ----
class StreamSource(ABC):
    kind: str                        # 'esf' | 'netflow'
    requires_tier: str
    def subscribe(self, device: Device) -> Iterator[Record]: ...
    def health(self) -> SourceHealth: ...

# ---- hunt: Strategy ----
class Analyzer(ABC):
    id: str
    version: str
    accepts: tuple[str, ...]         # artifact kinds
    def analyze(self, artifact: Artifact) -> list[Finding]: ...
```

`RawBundle.collected` is the D6 fix: the snapshot's `capabilities` column is
written from this set, never from a declared constant.

## 5. Diff — unchanged

```text
diff(A, B):
    shared = A.capabilities ∩ B.capabilities
    for category in shared:
        added   = B.keys - A.keys
        removed = A.keys - B.keys
        changed = keys in both where item_hash differs
    categories in only one snapshot → scope note, NEVER an event
```

Pure function. Ported as-is; it was correct.

## 6. Hash chain — unchanged, narrower input

```text
row_hash = sha256(prev_row_hash ‖ canonical_json(event_core_fields))
```

Core fields gain `source` and `ref_id`. Batch ordered by
`(source, category, subject_key)` for determinism. `psm db verify` walks
`events` only — findings and flows are outside the chain by design (D4).

## 7. Rules engine

Ported predicate set (`eq`, `in`, `prefix_any`, `has_any`, `exists`) plus the
restricted `a.X == b.Y` join. Two extensions:

```yaml
# over flows
- id: new-host-for-app
  severity: warning
  title: "App contacted a host it has never contacted before"
  match:
    source: flowlog
    where:
      flow.first_contact: true
      flow.app_pkg: { exists: true }

# over findings
- id: yara-hit-on-new-apk
  severity: alert
  title: "YARA rule matched a newly installed APK"
  correlate:
    a: { source: hunt,      where: { finding.verdict: ["suspicious","malicious"] } }
    b: { source: inventory, category: application, action: added }
    join: a.artifact.subject_key == b.subject_key
```

Path predicates route through the platform-aware `norm_path`, using the
**event's device platform** rather than a hardcoded one.

## 8. CLI

```text
psm device add|list|remove
psm doctor [DEVICE]              # tiers satisfied, what each missing tier adds

# inventory
psm baseline [DEVICE]
psm scan [DEVICE] [--against baseline|last] [--modules m1,m2] [--json]
psm watch --before-after [DEVICE]        # snapshot → keypress → snapshot → diff
psm persistence [DEVICE] [--diff]

# hunt
psm hunt [DEVICE] [--new|--all] [--analyzers yara,apk,vt] [--pull-apks]
psm hunt findings [--verdict malicious] [--since 7d]
psm hunt rescan                  # re-run updated analyzers over known artifacts

# flowlog
psm flow start|stop|status       # supervise the capture legs
psm flow top [--last 24h] [--by app|host]
psm flow app <pkg> [--last 7d]
psm flow host <hostname>
psm flow export [--format jsonl] PATH

# shared
psm timeline [--device D] [--last 7d] [--source inventory|hunt|flowlog|esf]
psm explain EVENT_ID
psm alerts [--status open] [--ack ID] [--close ID]
psm report daily [--out DIR]
psm db verify | compact | vacuum
```

Exit codes: `0` clean · `1` error · `2` warnings/gaps · `3` alerts.

## 9. Paths

```text
~/Library/Application Support/psm/
├── psm.sqlite
├── config.yaml
├── rules/            # user YAML rules (builtin ship in-package)
├── yara/             # user YARA rules
├── staging/          # pulled APKs awaiting analysis
├── reports/
└── logs/
```

## 10. Testing strategy

- **Golden files per normalizer** — recorded `dumpsys` per Android version,
  recorded macOS plist/TCC/Preferences fixtures → expected items.
- **Property tests on diff** — `diff(A,A) == ∅`; added/removed symmetry.
- **Chain tests** — mutate any event row, `verify` must fail at that id.
- **Regression tests for every v1 defect** — see PLAN Phase 0. Each of the six
  gets a named test that fails against the v1 behaviour.
- **Capability-derivation test** — collect with a module absent, assert zero
  phantom `removed` events (the D6 reproduction).
- **Per-item guard test** — one malformed plist in a directory of valid ones
  must yield N-1 items plus one gap, never zero items.
- **Flow correlation test** — synthetic router + device flows, assert the join
  attributes correctly and that unmatched flows survive as unattributed.
- **Fuzz** — hostile input to the VPN agent's log parser and the pcap decoder.
