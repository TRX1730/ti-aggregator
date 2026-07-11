# TI Aggregator — platforma threat intelligence

[![CI](https://github.com/TRX1730/ti-aggregator/actions/workflows/ci.yml/badge.svg)](https://github.com/TRX1730/ti-aggregator/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Modularna platforma threat intelligence. Trzy moduły na wspólnym rdzeniu (baza, API, szyna zdarzeń, powłoka UI), architektura **event-driven** (SSE + Postgres NOTIFY) — od workera po interfejs wszystko reaguje na zdarzenia, bez pollingu.

> Projekt budowany jako portfolio + nauka backendu + praktyczne narzędzie recon/CTI.

## Moduły

- **Intel** — rejestr IOC (IP, domena, hash, URL) + automatyczne wzbogacanie z 11+ źródeł, **ocena ryzyka**, **pivoty** (powiązania przez wspólne IP z oceną wiarygodności), eksport **STIX 2.1** (kompatybilny z MISP).
- **Recon** — powierzchnia ataku celu: odkrywanie subdomen (crt.sh + brute-force) + **pasywne sprawdzenia ekspozycji** (findings z severity), status skanu na żywo.
- **Przegląd** — świadomość sytuacyjna: liczniki + priorytety (findings CRITICAL/HIGH) + IOC oznaczone jako Tor.

## Źródła wzbogaceń (Intel)

| Źródło | Dotyczy | Co daje |
|--------|---------|---------|
| `dns` | ip, domena | DNS forward / reverse |
| `whois` | ip, domena | RDAP: kraj, ASN, handle rejestru |
| `dns_records` | domena | MX, NS, TXT + SPF/DMARC |
| `tor` | ip | czy IP to węzeł wyjściowy Tora (lista Tor Project) |
| `cdn` | domena | CDN/WAF (Cloudflare, Akamai, Fastly, CloudFront) + heurystyka origin |
| `crt` | domena | subdomeny z Certificate Transparency (crt.sh) |
| `tech` | domena, URL | fingerprint: frontend, backend, CMS, e-commerce, hosting, API/GraphQL |
| `wayback` | domena | historyczne URL-e (archive.org) |
| `geoip` | ip | geolokalizacja + ASN → prefiksy (ip-api + RIPEstat) |
| `blocklist` | ip, domena | CERT Polska (Lista ostrzeżeń) + abuse.ch (URLhaus, Feodo Tracker) |
| `virustotal` * | ip, domena, hash | reputacja 70+ silników AV + lista wykryć (**wymaga klucza API**) |

`*` — jedyne źródło wymagające klucza. Pozostałe są **bezkluczowe** i działają od razu.

## Recon — pasywne checki

Odsłonięte `/.env`, `/.git/config`, `/.aws/credentials` · panele admin · pliki backup · directory listing · `robots.txt` · Swagger/OpenAPI · brakujące nagłówki bezpieczeństwa · verbose `Server` · wewnętrzne IP (nagłówki + body) · **subdomain takeover** · mining sekretów w JS · **DNS zone transfer (AXFR)**.

> Wyłącznie pasywne / lekkie sprawdzenia (pojedynczy GET). Aktywne ataki (traversal, JWT, złośliwy input) świadomie **nie** są automatyzowane. Skanuj tylko domeny, do których masz prawo.

## Ocena ryzyka

Przejrzysty, wyjaśniony wynik z sygnałów: węzeł Tor, świeżo zarejestrowana domena, podejrzana etykieta źródła, **trafienie na blackliście CTI (+50)**, **VirusTotal (per liczba wykryć)**.

## Konfiguracja — klucze API (opcjonalne)

Platforma działa out-of-the-box bez żadnych kluczy (11 bezkluczowych źródeł). Aby włączyć **VirusTotal**:

```bash
cp .env.example .env
```

W pliku `.env` wpisz swój klucz przy `VT_API_KEY=` (darmowe konto na [virustotal.com](https://www.virustotal.com), limit 500 zapytań/dobę). `.env` jest w `.gitignore` — **klucz nigdy nie trafia do repo**. Bez klucza karta `virustotal` pokazuje komunikat, a reszta źródeł działa normalnie.

## Architektura

```
                 ┌──────────────┐
   przeglądarka  │  Frontend    │  Intel / Recon / Przegląd (HTML/JS w binarce API)
                 │  + SSE       │◄─────────── zdarzenia na żywo
                 └──────┬───────┘
                        │ REST/JSON
                 ┌──────┴───────┐
                 │   API (Go)   │  CRUD, pivoty, ryzyko, STIX, LISTEN→SSE
                 └──────┬───────┘
                        │
        ┌───────────────┼───────────────┐
   ┌────┴─────┐   ┌─────┴──────┐   ┌─────┴────────┐
   │ Postgres │◄──│  worker    │   │ recon-worker │
   │ (JSONB)  │NOT│ (wzbogaca) │   │ (skanuje)    │
   └──────────┘IFY└────────────┘   └──────────────┘
```

## Stack

- **Backend:** Go (stdlib `net/http`, `pgx`)
- **Workery:** Python (`psycopg`, `requests`, `dnspython`)
- **Baza:** PostgreSQL (dane w JSONB)
- **Frontend:** czysty HTML/CSS/JS, wbudowany w binarkę Go (`go:embed`)
- **Uruchomienie:** Docker + docker-compose

## Uruchomienie

```bash
docker compose up -d --build
# migracje (pierwszy raz):
for f in migrations/*.sql; do docker compose exec -T db psql -U ti -d ti < "$f"; done
```

- Dashboard: http://localhost:8080/
- Adminer (podgląd bazy): http://localhost:8081

Pełna instrukcja: [USAGE.md](USAGE.md)

## API (wybrane)

| Metoda | Ścieżka | Opis |
|--------|---------|------|
| `POST`/`GET`/`DELETE` | `/iocs`, `/iocs/{id}` | CRUD wskaźników |
| `GET` | `/iocs/{id}/pivots` | powiązania |
| `POST` | `/import` | import IOC z wklejonych logów |
| `GET` | `/export/stix` | eksport STIX 2.1 |
| `POST`/`GET`/`DELETE` | `/targets`, `/targets/{id}` | cele recon |
| `GET` | `/overview` | dane do zakładki Przegląd |
| `GET` | `/events` | strumień SSE |

## Wybrane decyzje inżynierskie

- **Modularny monolit** — trzy moduły, wspólny rdzeń; mikroserwisy byłyby przy tej skali nadmiarowym narzutem.
- **Rozszerzalny worker** — nowe źródło wzbogaceń = jedna funkcja + jedna linijka na liście.
- **Event-driven** — Postgres LISTEN/NOTIFY + SSE zamiast pollingu.
- **Ocena wiarygodności pivotów** — wspólne IP na CDN oznaczane jako słabe powiązanie.
- **Frontend w binarce** (`go:embed`) — jeden artefakt, brak CORS.
- **Sekrety poza repo** — klucze przez `.env` (`${VAR}` w compose, `os.environ` w kodzie).

## Ograniczenia (świadome)

- `tech` to fingerprint orientacyjny, nie pełny Wappalyzer.
- Heurystyka origin za CDN bywa nieskuteczna (CDN celowo ukrywa origin).
- Recon jest pasywny — aktywne ataki nie są automatyzowane.
- Eksport STIX jest; pełny serwer TAXII 2.1 — nie (bundle wystarcza do MISP).

## Licencja

MIT — patrz [LICENSE](LICENSE).
