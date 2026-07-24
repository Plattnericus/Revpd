-- Initial schema. See CLAUDE.md section 4.

CREATE TABLE users (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    username          TEXT    NOT NULL UNIQUE,
    display_name      TEXT    NOT NULL DEFAULT '',
    password_hash     TEXT    NOT NULL,
    role              TEXT    NOT NULL DEFAULT 'user',   -- 'admin' | 'user'
    rdp_hint          TEXT    NOT NULL DEFAULT '',       -- alias matched against mstshash
    totp_secret_enc   BLOB,
    totp_last_counter INTEGER NOT NULL DEFAULT 0,        -- replay guard, see internal/mfa/totp
    status            TEXT    NOT NULL DEFAULT 'active', -- 'active' | 'locked' | 'disabled'
    created_at        INTEGER NOT NULL,
    CHECK (role IN ('admin', 'user')),
    CHECK (status IN ('active', 'locked', 'disabled'))
);

-- Matched case-insensitively against the mstshash cookie, so index it that way.
CREATE UNIQUE INDEX idx_users_rdp_hint ON users (lower(rdp_hint)) WHERE rdp_hint <> '';

CREATE TABLE backup_codes (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id   INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash TEXT    NOT NULL,
    used_at   INTEGER
);
CREATE INDEX idx_backup_codes_user ON backup_codes (user_id) WHERE used_at IS NULL;

CREATE TABLE webauthn_creds (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    credential_id BLOB    NOT NULL UNIQUE,
    public_key    BLOB    NOT NULL,
    sign_count    INTEGER NOT NULL DEFAULT 0,
    name          TEXT    NOT NULL DEFAULT '',
    created_at    INTEGER NOT NULL
);
CREATE INDEX idx_webauthn_user ON webauthn_creds (user_id);

CREATE TABLE targets (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT    NOT NULL UNIQUE,
    hostname      TEXT    NOT NULL DEFAULT '',
    ip            TEXT    NOT NULL,
    rdp_port      INTEGER NOT NULL DEFAULT 3389,
    mac           TEXT    NOT NULL,
    wol_broadcast TEXT    NOT NULL DEFAULT '255.255.255.255',
    wol_port      INTEGER NOT NULL DEFAULT 9,
    boot_timeout_s INTEGER NOT NULL DEFAULT 120,
    icon          TEXT    NOT NULL DEFAULT 'monitor',
    notes         TEXT    NOT NULL DEFAULT '',
    created_at    INTEGER NOT NULL
);

CREATE TABLE user_targets (
    user_id   INTEGER NOT NULL REFERENCES users (id)   ON DELETE CASCADE,
    target_id INTEGER NOT NULL REFERENCES targets (id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, target_id)
);

CREATE TABLE grants (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users (id)   ON DELETE CASCADE,
    target_id  INTEGER NOT NULL REFERENCES targets (id) ON DELETE CASCADE,
    src_ip     TEXT    NOT NULL,
    token_hash TEXT    NOT NULL,
    mode       TEXT    NOT NULL,                        -- 'portal' | 'jit' | 'rdgw'
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER,
    revoked_at  INTEGER,
    CHECK (mode IN ('portal', 'jit', 'rdgw'))
);
-- The relay hits this on every inbound connection, so keep it cheap.
CREATE INDEX idx_grants_lookup ON grants (src_ip, expires_at) WHERE revoked_at IS NULL;

CREATE TABLE sessions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash TEXT    NOT NULL UNIQUE,
    src_ip     TEXT    NOT NULL,
    user_agent TEXT    NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL
);
CREATE INDEX idx_sessions_expiry ON sessions (expires_at);

CREATE TABLE rdp_sessions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    grant_id     INTEGER REFERENCES grants (id)  ON DELETE SET NULL,
    target_id    INTEGER REFERENCES targets (id) ON DELETE SET NULL,
    src_ip       TEXT    NOT NULL,
    started_at   INTEGER NOT NULL,
    ended_at     INTEGER,
    bytes_in     INTEGER NOT NULL DEFAULT 0,
    bytes_out    INTEGER NOT NULL DEFAULT 0,
    close_reason TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX idx_rdp_sessions_live ON rdp_sessions (started_at) WHERE ended_at IS NULL;

CREATE TABLE jit_requests (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_hint       TEXT    NOT NULL DEFAULT '',
    matched_user_id INTEGER REFERENCES users (id)   ON DELETE SET NULL,
    target_id       INTEGER REFERENCES targets (id) ON DELETE SET NULL,
    src_ip          TEXT    NOT NULL,
    state           TEXT    NOT NULL DEFAULT 'pending',
    created_at      INTEGER NOT NULL,
    decided_at      INTEGER,
    decided_via     TEXT    NOT NULL DEFAULT '',
    CHECK (state IN ('pending', 'approved', 'denied', 'timeout'))
);
CREATE INDEX idx_jit_pending ON jit_requests (src_ip) WHERE state = 'pending';

CREATE TABLE settings (
    key       TEXT PRIMARY KEY,
    value_enc BLOB NOT NULL
);

-- Append-only and hash-chained. Never add UPDATE or DELETE paths to this table.
CREATE TABLE audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          INTEGER NOT NULL,
    actor       TEXT    NOT NULL,
    action      TEXT    NOT NULL,
    object      TEXT    NOT NULL DEFAULT '',
    src_ip      TEXT    NOT NULL DEFAULT '',
    detail_json TEXT    NOT NULL DEFAULT '{}',
    prev_hash   TEXT    NOT NULL,
    hash        TEXT    NOT NULL
);
CREATE INDEX idx_audit_ts ON audit_log (ts);
