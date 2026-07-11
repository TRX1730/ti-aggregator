CREATE TABLE targets (
    id              BIGSERIAL PRIMARY KEY,
    domain          TEXT NOT NULL UNIQUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_scanned_at TIMESTAMPTZ
);

CREATE TABLE assets (
    id          BIGSERIAL PRIMARY KEY,
    target_id   BIGINT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    type        TEXT NOT NULL DEFAULT 'subdomain',
    value       TEXT NOT NULL,
    resolved_ip TEXT,
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT assets_unique UNIQUE (target_id, value)
);

CREATE INDEX idx_assets_target_id ON assets (target_id);
