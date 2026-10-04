-- PSM v2 schema. Not a migration from v1: canonical-JSON v2 and platform-aware
-- path normalization invalidate every v1 item hash and the whole event chain,
-- so there is no meaningful upgrade path. db.py refuses to open a v1 database.

CREATE TABLE devices (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    platform    TEXT NOT NULL CHECK (platform IN ('macos','android')),
    identifier  TEXT NOT NULL,
    tiers       TEXT NOT NULL DEFAULT '[]',
    created_at  TEXT NOT NULL,
    meta        TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE snapshots (
    id           INTEGER PRIMARY KEY,
    device_id    INTEGER NOT NULL REFERENCES devices(id),
    taken_at     TEXT NOT NULL,
    kind         TEXT NOT NULL CHECK (kind IN ('baseline','scan','before','after')),
    capabilities TEXT NOT NULL,          -- derived from RawBundle.collected, never declared
    tool_version TEXT NOT NULL,
    gaps         TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX idx_snapshots_device ON snapshots(device_id, id DESC);

CREATE TABLE items (
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

-- Chained. Conclusions only: inventory diffs, promoted findings, flow alerts.
CREATE TABLE events (
    id            INTEGER PRIMARY KEY,
    device_id     INTEGER NOT NULL REFERENCES devices(id),
    ts            TEXT NOT NULL,
    source        TEXT NOT NULL
                    CHECK (source IN ('inventory','hunt','flowlog','esf')),
    category      TEXT NOT NULL,
    action        TEXT NOT NULL CHECK (action IN ('added','removed','changed','observed')),
    subject_key   TEXT NOT NULL,
    before_hash   TEXT REFERENCES items(hash),
    after_hash    TEXT REFERENCES items(hash),
    snap_from     INTEGER REFERENCES snapshots(id),
    snap_to       INTEGER REFERENCES snapshots(id),
    ref_id        INTEGER,
    severity      TEXT NOT NULL DEFAULT 'info'
                    CHECK (severity IN ('info','notice','warning','alert')),
    prev_row_hash TEXT NOT NULL,
    row_hash      TEXT NOT NULL UNIQUE
);
CREATE INDEX idx_events_device_ts ON events(device_id, ts);
CREATE INDEX idx_events_subject   ON events(subject_key);
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

-- ---- hunt ----

CREATE TABLE artifacts (
    id          INTEGER PRIMARY KEY,
    device_id   INTEGER NOT NULL REFERENCES devices(id),
    kind        TEXT NOT NULL CHECK (kind IN ('file','apk','dylib','script')),
    subject_key TEXT NOT NULL,
    sha256      TEXT,
    size        INTEGER,
    local_path  TEXT,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    UNIQUE (device_id, subject_key)
);
CREATE INDEX idx_artifacts_sha ON artifacts(sha256);

-- Not chained: re-evaluable by design. The UNIQUE makes re-running idempotent.
CREATE TABLE findings (
    id               INTEGER PRIMARY KEY,
    artifact_id      INTEGER NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    analyzer_id      TEXT NOT NULL,
    analyzer_version TEXT NOT NULL,
    rule_id          TEXT,
    verdict          TEXT NOT NULL
                       CHECK (verdict IN ('clean','suspicious','malicious','unknown')),
    confidence       TEXT NOT NULL DEFAULT 'medium'
                       CHECK (confidence IN ('low','medium','high')),
    evidence         TEXT NOT NULL DEFAULT '{}',
    ts               TEXT NOT NULL,
    UNIQUE (artifact_id, analyzer_id, analyzer_version, rule_id)
);
CREATE INDEX idx_findings_verdict ON findings(verdict, ts);

CREATE TABLE known_good_hashes (
    sha256 TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    label  TEXT
);

-- ---- flowlog ----

CREATE TABLE flows (
    id         INTEGER PRIMARY KEY,
    device_id  INTEGER NOT NULL REFERENCES devices(id),
    ts         TEXT NOT NULL,
    leg        TEXT NOT NULL CHECK (leg IN ('router','device')),
    proto      TEXT NOT NULL,
    src_port   INTEGER,
    dst_ip     TEXT NOT NULL,
    dst_port   INTEGER NOT NULL,
    hostname   TEXT,
    -- How the hostname was determined, weakest inference last: 'sni' and
    -- 'dns-query' are observed on the connection itself; 'dns-cache' infers from
    -- an earlier DNS answer, and several names can share one address; 'rdns' is a
    -- reverse lookup, which for CDN addresses is often unrelated to the name the
    -- client actually asked for. Kept so a guess is never shown as a fact.
    hostname_source TEXT CHECK (hostname_source IN ('sni','dns-query','dns-cache','rdns')),
    sni_status TEXT CHECK (sni_status IN ('plain','ech','none')),
    app_uid    INTEGER,
    app_pkg    TEXT,
    bytes_out  INTEGER NOT NULL DEFAULT 0,
    bytes_in   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_flows_ts   ON flows(device_id, ts);
CREATE INDEX idx_flows_dst  ON flows(dst_ip, ts);
CREATE INDEX idx_flows_host ON flows(hostname);

CREATE TABLE flow_rollups (
    id         INTEGER PRIMARY KEY,
    device_id  INTEGER NOT NULL REFERENCES devices(id),
    hour       TEXT NOT NULL,
    app_pkg    TEXT,
    hostname   TEXT,
    dst_ip     TEXT,
    dst_port   INTEGER,
    flow_count INTEGER NOT NULL,
    bytes_out  INTEGER NOT NULL,
    bytes_in   INTEGER NOT NULL,
    first_ts   TEXT NOT NULL,
    last_ts    TEXT NOT NULL,
    UNIQUE (device_id, hour, app_pkg, hostname, dst_ip, dst_port)
);
CREATE INDEX idx_rollup_app  ON flow_rollups(app_pkg, hour);
CREATE INDEX idx_rollup_host ON flow_rollups(hostname, hour);

-- ---- support ----

CREATE TABLE file_hash_cache (
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    path_norm TEXT NOT NULL,
    size      INTEGER NOT NULL,
    mtime_ns  INTEGER NOT NULL,
    file_id   INTEGER NOT NULL,
    sha256    TEXT NOT NULL,
    PRIMARY KEY (device_id, path_norm)
);

CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);

INSERT INTO meta (key, value) VALUES ('schema_version', '1');
INSERT INTO meta (key, value) VALUES ('chain_head', '');
INSERT INTO meta (key, value) VALUES ('canonical_json_version', '2');
INSERT INTO meta (key, value) VALUES ('psm_major', '2');
