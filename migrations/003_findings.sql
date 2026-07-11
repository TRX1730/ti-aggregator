CREATE TABLE findings (
    id         BIGSERIAL PRIMARY KEY,
    target_id  BIGINT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    asset      TEXT NOT NULL,
    severity   TEXT NOT NULL,
    title      TEXT NOT NULL,
    detail     TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT findings_unique UNIQUE (target_id, asset, title)
);

CREATE INDEX idx_findings_target_id ON findings (target_id);
