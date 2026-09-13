CREATE TABLE file_hash_cache (
    device_id  INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    path_norm  TEXT NOT NULL,
    size       INTEGER NOT NULL,
    mtime_ns   INTEGER NOT NULL,
    file_id    INTEGER NOT NULL,
    sha256     TEXT NOT NULL,
    PRIMARY KEY (device_id, path_norm)
);
