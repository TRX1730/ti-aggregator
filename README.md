# TI Aggregator

[![CI](https://github.com/TRX1730/ti-aggregator/actions/workflows/ci.yml/badge.svg)](https://github.com/TRX1730/ti-aggregator/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Samodzielne narzędzie threat intelligence: zbiera wskaźniki zagrożeń (IOC), **automatycznie wzbogaca** je z wielu źródeł, wykrywa **powiązania** między nimi i eksportuje w formacie **STIX 2.1** (kompatybilnym z MISP). Architektura **event-driven** — od workera po interfejs wszystko reaguje na zdarzenia, bez pollingu.

> Projekt budowany jako portfolio + nauka backendu + praktyczne narzędzie recon/TI.

---

## Co potrafi

- **Rejestr IOC** — dodawanie i przeglądanie wskaźników (IP, domena, hash, URL) z walidacją.
- **Automatyczne wzbogacanie** w tle, z 6 źródeł (patrz niżej).
- **Pivoty** — wykrywanie powiązań między IOC przez wspólne IP, z **oceną wiarygodności** (powiązania przez IP CDN oznaczone jako niepewne).
- **Graf powiązań** — wizualizacja sieci wskaźników.
- **Realtime** — wzbogacenia pojawiają się w interfejsie na żywo (SSE + Postgres NOTIFY).
- **Eksport STIX 2.1** — bundle gotowy do importu w MISP, ze stabilnymi identyfikatorami.

## Źródła wzbogaceń

| Źródło | Dotyczy | Co daje |
|--------|---------|---------|
| `dns` | ip, domena | rozwiązanie DNS / reverse DNS |
| `whois` | ip, domena | dane rejestracyjne przez RDAP (kraj, ASN, handle) |
| `tor` | ip | czy IP to węzeł wyjściowy Tora (lista Tor Project) |
| `cdn` | domena | wykrycie CDN/WAF (Cloudflare, Akamai, Fastly, CloudFront) + heurystyka origin |
| `crt` | domena | subdomeny z Certificate Transparency (crt.sh) |
| `tech` | domena, URL | fingerprint stacku: frontend, backend, CMS, API/GraphQL, usługi |

## Architektura

```
                 ┌──────────────┐
   przeglądarka  │  Frontend    │  dashboard (HTML/JS, wbudowany w binarkę API)
                 │  + SSE       │◄─────────── zdarzenia na żywo
                 └──────┬───────┘
                        │ REST/JSON
                 ┌──────┴───────┐
                 │   API (Go)   │  CRUD, pivoty, eksport STIX, LISTEN→SSE
                 └──────┬───────┘
                        │
             ┌──────────┴──────────┐
       ┌─────┴──────┐        ┌─────┴──────┐
       │  Postgres  │◄───────│  Worker    │  Python — wzbogaca IOC w tle,
       │  (JSONB)   │ NOTIFY │  (polling) │  po zapisie wysyła NOTIFY
       └────────────┘        └────────────┘
```

Przepływ zdarzeń: worker zapisuje wzbogacenie → `NOTIFY` w Postgresie → API (`LISTEN`) → **SSE** do przeglądarki. Zero odpytywania w kółko.

## Stack

- **Backend:** Go (stdlib `net/http`, `pgx`)
- **Worker:** Python (`psycopg`, `requests`)
- **Baza:** PostgreSQL (dane w JSONB)
- **Frontend:** czysty HTML/CSS/JS, wbudowany w binarkę Go przez `go:embed`
- **Uruchomienie:** Docker + docker-compose

## Uruchomienie

```bash
docker compose up -d --build
```

- Dashboard: http://localhost:8080/
- Podgląd bazy (Adminer): http://localhost:8081

Pełna instrukcja obsługi: [USAGE.md](USAGE.md)

## API

| Metoda | Ścieżka | Opis |
|--------|---------|------|
| `GET` | `/health` | status API + baza |
| `POST` | `/iocs` | dodaj IOC |
| `GET` | `/iocs` | lista (filtr `?type=`) |
| `GET` | `/iocs/{id}` | IOC + wzbogacenia |
| `GET` | `/iocs/{id}/pivots` | powiązania |
| `GET` | `/export/stix` | eksport STIX 2.1 |
| `GET` | `/events` | strumień SSE |

## Wybrane decyzje inżynierskie

- **Rozszerzalny worker** — dodanie nowego źródła wzbogaceń to jedna funkcja + jedna linijka na liście enricherów.
- **Event-driven zamiast pollingu** — Postgres LISTEN/NOTIFY + SSE (lekka alternatywa dla WebSocketów, kierunek serwer→klient).
- **Ocena wiarygodności pivotów** — wspólne IP na CDN jest oznaczane jako słabe powiązanie (na CDN siedzą miliony niepowiązanych domen).
- **Frontend w binarce** (`go:embed`) — jeden artefakt serwuje API i UI, brak CORS, brak osobnego kontenera.
- **Stabilne STIX id** (UUIDv5) — brak duplikatów przy ponownym imporcie do MISP.

## Ograniczenia (świadome)

- `tech` to fingerprint orientacyjny, nie pełny Wappalyzer — niektóre backendy (np. Go) nie zdradzają się w nagłówkach.
- Heurystyka origin za CDN bywa nieskuteczna — CDN celowo ukrywa origin; wyniki są oznaczone jako niepewne.
- Eksport STIX jest zaimplementowany; pełny serwer TAXII 2.1 — nie (bundle wystarcza do importu w MISP).

## Licencja

MIT — patrz [LICENSE](LICENSE).
