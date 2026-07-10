CREATE TABLE iocs (
    id         BIGSERIAL PRIMARY KEY,
    type       TEXT NOT NULL,
    value      TEXT NOT NULL,
    source     TEXT,
    tags       TEXT[] DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT iocs_type_valid CHECK (type IN ('ip', 'domain', 'hash', 'url')),
    CONSTRAINT iocs_unique UNIQUE (type, value)
);

CREATE TABLE enrichments (
    id         BIGSERIAL PRIMARY KEY,
    ioc_id     BIGINT NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    source     TEXT NOT NULL,
    data       JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_enrichments_ioc_id ON enrichments (ioc_id);
