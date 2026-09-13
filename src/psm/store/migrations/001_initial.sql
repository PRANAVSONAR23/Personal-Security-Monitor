CREATE TABLE devices (
    id            INTEGER PRIMARY KEY,
    name          TEXT NOT NULL UNIQUE,
    platform      TEXT NOT NULL CHECK (platform IN ('windows','macos','android')),
    identifier    TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    meta          TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE snapshots (
    id            INTEGER PRIMARY KEY,
    device_id     INTEGER NOT NULL REFERENCES devices(id),
    taken_at      TEXT NOT NULL,
    kind          TEXT NOT NULL CHECK (kind IN ('baseline','scan','before','after')),
    capabilities  TEXT NOT NULL,
    tool_version  TEXT NOT NULL,
    gaps          TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE items (
    hash          TEXT PRIMARY KEY,
    category      TEXT NOT NULL,
    subject_key   TEXT NOT NULL,
    payload       TEXT NOT NULL
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
    action        TEXT NOT NULL CHECK (action IN ('added','removed','changed','observed')),
    subject_key   TEXT NOT NULL,
    before_hash   TEXT REFERENCES items(hash),
    after_hash    TEXT REFERENCES items(hash),
    snap_from     INTEGER REFERENCES snapshots(id),
    snap_to       INTEGER NOT NULL REFERENCES snapshots(id),
    severity      TEXT NOT NULL DEFAULT 'info'
                   CHECK (severity IN ('info','notice','warning','alert')),
    prev_row_hash TEXT NOT NULL,
    row_hash      TEXT NOT NULL UNIQUE
);
CREATE INDEX idx_events_device_ts ON events(device_id, ts);
CREATE INDEX idx_events_subject   ON events(subject_key);

CREATE TABLE alerts (
    id            INTEGER PRIMARY KEY,
    rule_id       TEXT NOT NULL,
    device_id     INTEGER NOT NULL REFERENCES devices(id),
    ts            TEXT NOT NULL,
    title         TEXT NOT NULL,
    detail        TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','ack','closed'))
);

CREATE TABLE alert_events (
    alert_id  INTEGER NOT NULL REFERENCES alerts(id),
    event_id  INTEGER NOT NULL REFERENCES events(id),
    PRIMARY KEY (alert_id, event_id)
);

CREATE TABLE known_good_hashes (
    sha256   TEXT PRIMARY KEY,
    source   TEXT NOT NULL,
    label    TEXT
);

CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

INSERT INTO meta (key, value) VALUES ('schema_version', '1');
INSERT INTO meta (key, value) VALUES ('chain_head', '');
INSERT INTO meta (key, value) VALUES ('canonical_json_version', '1');
