CREATE TABLE watchlist (
    id           BIGSERIAL PRIMARY KEY,
    kind         TEXT NOT NULL,
    ref_id       BIGINT NOT NULL,
    label        TEXT NOT NULL,
    sig          JSONB,
    last_checked TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT watchlist_unique UNIQUE (kind, ref_id)
);

CREATE TABLE alerts (
    id           BIGSERIAL PRIMARY KEY,
    watchlist_id BIGINT NOT NULL REFERENCES watchlist(id) ON DELETE CASCADE,
    severity     TEXT NOT NULL DEFAULT 'info',
    message      TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_alerts_watchlist ON alerts (watchlist_id);
