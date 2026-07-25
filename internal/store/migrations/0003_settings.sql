-- Settings an administrator can change from the dashboard.
--
-- revpd.yaml stays the source of truth for everything that shapes how the
-- gateway runs. This table is for the handful of choices that are an operator
-- preference rather than a deployment decision — starting with whether updates
-- install themselves — so they can be changed without editing a file on the
-- server and restarting.
CREATE TABLE IF NOT EXISTS app_settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_by TEXT NOT NULL DEFAULT ''
);
