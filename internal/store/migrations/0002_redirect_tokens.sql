-- Tokens handed to a client in a Server Redirection PDU.
--
-- Deliberately its own table rather than a grant mode: these live for seconds,
-- are single-use, and exist only to tie a redirected reconnect back to the
-- login that caused it.

CREATE TABLE redirect_tokens (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT    NOT NULL UNIQUE,
    user_id    INTEGER NOT NULL REFERENCES users (id)   ON DELETE CASCADE,
    target_id  INTEGER NOT NULL REFERENCES targets (id) ON DELETE CASCADE,
    src_ip     TEXT    NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at    INTEGER
);

-- The relay hits this on the reconnect, so keep the unused ones cheap to find.
CREATE INDEX idx_redirect_tokens_open ON redirect_tokens (token_hash) WHERE used_at IS NULL;
CREATE INDEX idx_redirect_tokens_expiry ON redirect_tokens (expires_at);
