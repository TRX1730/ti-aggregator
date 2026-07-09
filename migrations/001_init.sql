-- 001_init.sql
-- Pierwsza migracja: tworzy tabele "iocs" i "enrichments".
-- Uruchamiasz ten plik na bazie, a on buduje strukturę.

-- Tabela głównych wskaźników zagrożeń (IOC).
CREATE TABLE iocs (
    id         BIGSERIAL PRIMARY KEY,          -- unikalny numer wiersza, baza nadaje sama
    type       TEXT NOT NULL,                  -- rodzaj: ip / domain / hash / url
    value      TEXT NOT NULL,                  -- sama wartość, np. "185.220.101.5"
    source     TEXT,                           -- skąd to mamy (opcjonalne)
    tags       TEXT[] DEFAULT '{}',            -- lista tagów, np. {wordpress-scan, bot}
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Pilnuje, żeby type miał tylko dozwolone wartości.
    CONSTRAINT iocs_type_valid CHECK (type IN ('ip', 'domain', 'hash', 'url')),

    -- Nie chcemy dwa razy tego samego IOC (ten sam typ + wartość).
    CONSTRAINT iocs_unique UNIQUE (type, value)
);

-- Tabela wzbogaceń: dane dołożone do IOC (whois, DNS, VirusTotal...).
CREATE TABLE enrichments (
    id         BIGSERIAL PRIMARY KEY,
    ioc_id     BIGINT NOT NULL                 -- do którego IOC należy to wzbogacenie
               REFERENCES iocs(id)             -- KLUCZ OBCY: wskazuje wiersz w tabeli iocs
               ON DELETE CASCADE,              -- gdy skasujesz IOC, jego wzbogacenia znikają razem z nim
    source     TEXT NOT NULL,                  -- whois / dns / virustotal
    data       JSONB NOT NULL,                 -- surowa odpowiedź źródła, jako JSON
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Indeks przyspiesza szukanie wzbogaceń po ioc_id (częste zapytanie).
CREATE INDEX idx_enrichments_ioc_id ON enrichments (ioc_id);
