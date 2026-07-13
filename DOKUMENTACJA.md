# TI Aggregator — pełna dokumentacja kodu (przewodnik do rozmowy)

Ten dokument tłumaczy **całą platformę od ogółu do szczegółu**: architekturę, zależności, każdy plik, kluczowe fragmenty kodu, przepływy danych, definicje i najczęstsze pytania rozmowowe z odpowiedziami. Cel: żebyś umiał omówić i rozbudować projekt z głowy.

---

# CZĘŚĆ 1 — OGÓLNY OBRAZ

## 1.1 Co to jest

Platforma **threat intelligence (CTI)**. Zbiera **wskaźniki zagrożeń (IOC)** — adresy IP, domeny, hashe plików, URL — i **automatycznie je wzbogaca** danymi z wielu źródeł (DNS, whois, reputacja, feedy malware, Shodan, VirusTotal…), liczy **ocenę ryzyka**, wykrywa **powiązania (pivoty)** między wskaźnikami, prowadzi **recon** (rozpoznanie powierzchni ataku domeny) i **monitoruje** wybrane obiekty, alertując o zmianach.

## 1.2 Cztery moduły + instrukcja (zakładki UI)

- **Intel** — rejestr IOC + wzbogacanie (13 źródeł) + ryzyko + pivoty + eksport STIX.
- **Recon** — dla domeny-celu: odkrywanie subdomen + pasywne sprawdzenia ekspozycji → findings.
- **Przegląd** — dashboard: liczniki + priorytetowe findings + IOC z Tora.
- **Śledzenie** — watchlist wybranych IOC/celów + alerty na zmiany.
- **Instrukcja** — statyczny przewodnik w UI.

## 1.3 Architektura (modularny monolit, event-driven)

```
przeglądarka (Intel/Recon/Przegląd/Śledzenie)  ← SSE (zdarzenia na żywo)
        │ REST/JSON
   API (Go)  — CRUD, ryzyko, pivoty, STIX, LISTEN→SSE, serwuje frontend
        │
   PostgreSQL (JSONB)  ← NOTIFY ← workery (Python)
        ├─ worker           (wzbogaca IOC)
        ├─ recon-worker     (skanuje cele)
        └─ monitor-worker   (watchlist → alerty)
```

**Kluczowe określenie na rozmowę:** to **modularny monolit** — jeden system z wyraźnymi granicami modułów, nie mikroserwisy. Świadomy wybór: przy tej skali narzut operacyjny mikroserwisów (sieć, deploy, spójność danych) się nie opłaca, a granice modułów pozwalają rozbić je później, gdyby zaszła potrzeba (podejście „MonolithFirst" Martina Fowlera).

**Event-driven:** worker po zapisie wzbogacenia wysyła `NOTIFY` w Postgresie → API to słyszy (`LISTEN`) → wypycha zdarzenie do przeglądarki przez **SSE**. Zero pollingu w normalnej pracy.

## 1.4 Stack i zależności

| Warstwa | Technologia | Po co |
|---------|-------------|-------|
| Backend API | Go (stdlib `net/http`) | szybki, prosty serwer, routing 1.22 (metoda + `{param}`) |
| Sterownik DB | `github.com/jackc/pgx/v5` (+ `pgxpool`, `pgconn`) | połączenie z Postgresem, pula połączeń |
| Baza | PostgreSQL | relacyjna + `JSONB` na elastyczne dane wzbogaceń |
| Workery | Python | `psycopg` (DB), `requests` (HTTP), `dnspython` (DNS/AXFR) |
| Frontend | czysty HTML/CSS/JS | wbudowany w binarkę Go przez `//go:embed`, zero build-stepu |
| Uruchomienie | Docker + docker-compose | pięć usług: db, api, worker, recon-worker, monitor-worker, adminer |

---

# CZĘŚĆ 2 — BAZA DANYCH (migracje)

Migracje to ponumerowane pliki SQL w `migrations/`. Uruchamiasz je po kolei; baza „dorasta". Nie edytujesz starych — dokładasz nowe.

## 2.1 `001_init.sql` — rdzeń Intel

```sql
CREATE TABLE iocs (
    id BIGSERIAL PRIMARY KEY, type TEXT, value TEXT, source TEXT,
    tags TEXT[] DEFAULT '{}', created_at ..., updated_at ...,
    CONSTRAINT iocs_type_valid CHECK (type IN ('ip','domain','hash','url')),
    CONSTRAINT iocs_unique UNIQUE (type, value)
);
CREATE TABLE enrichments (
    id BIGSERIAL PRIMARY KEY,
    ioc_id BIGINT REFERENCES iocs(id) ON DELETE CASCADE,
    source TEXT, data JSONB, created_at ...
);
CREATE INDEX idx_enrichments_ioc_id ON enrichments (ioc_id);
```

- `iocs` — wskaźniki. `CHECK` pilnuje dozwolonych typów, `UNIQUE(type,value)` blokuje duplikaty.
- `enrichments` — wyniki wzbogaceń, po jednym wierszu na źródło. **`data JSONB`** = elastyczny JSON (każde źródło ma inny kształt). **`ON DELETE CASCADE`** = skasowanie IOC kasuje jego wzbogacenia.

## 2.2 `002_recon.sql` — `targets`, `assets`
Cele recon (domeny) i odkryte assety (subdomeny) z `first_seen`/`last_seen` (historia zmian).

## 2.3 `003_findings.sql` — `findings`
Znaleziska recon: `severity` (critical/high/medium/low), `title`, `detail`. `UNIQUE(target_id, asset, title)` = brak duplikatów przy re-skanie.

## 2.4 `004_target_status.sql`
`ALTER TABLE targets ADD COLUMN status` — `pending` / `scanning` / `done` (status skanu na żywo).

## 2.5 `005_watchlist.sql` — `watchlist`, `alerts`
`watchlist` (co śledzimy + `sig JSONB` = ostatni snapshot) i `alerts` (wygenerowane przy zmianie).

**Definicja JSONB:** binarny JSON w Postgresie, z indeksowaniem i operatorami (`data->'x'`, `data->>'x'`, `jsonb_array_elements_text(...)`). Używamy go, bo dane wzbogaceń mają różny kształt zależnie od źródła.

---

# CZĘŚĆ 3 — BACKEND API (Go)

Wszystkie pliki w `api/`, jeden pakiet `main`. Jeden binarny serwer.

## 3.1 `main.go` — wejście, wiring, routing

**Struktura `server`** trzyma zależności współdzielone przez handlery:
```go
type server struct {
    db  *pgxpool.Pool  // pula połączeń do Postgresa
    hub *hub           // rozsyła zdarzenia SSE
}
```
To wzorzec **dependency injection przez strukturę** — handlery są metodami `(s *server)`, więc mają `s.db` i `s.hub` bez zmiennych globalnych.

**`//go:embed web`** — dyrektywa kompilatora (NIE komentarz), która wkompilowuje folder `web/` (frontend) w binarkę:
```go
//go:embed web
var staticFiles embed.FS
```

**`main()`** czyta config ze zmiennych środowiskowych (`API_PORT`, `DATABASE_URL`), tworzy pulę połączeń, startuje goroutine nasłuchującą NOTIFY, rejestruje trasy i serwuje:
```go
pool, _ := pgxpool.New(context.Background(), dbURL)
srv := &server{db: pool, hub: newHub()}
go srv.runListener(context.Background(), dbURL)   // LISTEN→SSE w tle
mux := http.NewServeMux()
mux.HandleFunc("GET /iocs/{id}", srv.getIOC)      // routing 1.22: metoda + {param}
...
webRoot, _ := fs.Sub(staticFiles, "web")
mux.Handle("GET /", http.FileServerFS(webRoot))   // frontend spod "/"
http.ListenAndServe(":"+port, mux)
```

**Definicja: pula połączeń (`pgxpool`)** — zestaw gotowych połączeń do bazy wielokrotnego użytku. Szybsze niż łączyć się od nowa przy każdym żądaniu.

**Routing Go 1.22:** `mux.HandleFunc("GET /iocs/{id}", ...)` — wbudowany router obsługuje metodę HTTP i parametry ścieżki (`{id}` czytasz przez `r.PathValue("id")`). Bardziej szczegółowe trasy (`/iocs/{id}`) mają pierwszeństwo przed `GET /` (frontend).

## 3.2 `respond.go` — helpery odpowiedzi
```go
func writeJSON(w, code, v any) { ...ustaw nagłówek, kod, json.NewEncoder(w).Encode(v) }
func writeError(w, code, msg)  { writeJSON(w, code, map[string]string{"error": msg}) }
```
Dwie funkcje używane wszędzie — jednolity format odpowiedzi i błędów. `any` = dowolny typ.

## 3.3 `iocs.go` — CRUD wskaźników + odczyt z wzbogaceniami

**Typy:**
```go
type IOC struct { ID; Type; Value; Source; CreatedAt }               // wiersz iocs
type Enrichment struct { ID; Source; Data json.RawMessage; ...; Mitre *mitre }
type IOCWithEnrichments struct { IOC; Enrichments []Enrichment; Risk riskResult }  // embedding
```
- **`json.RawMessage`** dla `Data` — surowy JSON z bazy przepuszczany „jak jest" (bez base64, bez re-parsowania).
- **Embedding** (`IOCWithEnrichments` zawiera `IOC`) — w JSON pola IOC lądują na wierzchu + dochodzą `enrichments`, `risk`.

**`validateInput`** — walidacja: typ z dozwolonych, `value` niepuste, dla `ip` sprawdzenie `net.ParseIP`.

**`createIOC`** — czyta JSON z ciała, waliduje, `INSERT ... RETURNING`. Kluczowa obsługa błędu duplikatu:
```go
var pgErr *pgconn.PgError
if errors.As(err, &pgErr) && pgErr.Code == "23505" {   // 23505 = unique_violation
    writeError(w, http.StatusConflict, "taki IOC już istnieje")   // 409, nie 500
}
```
`errors.As` wyciąga konkretny typ błędu Postgresa, żeby odczytać `.Code`. To rozróżnia „duplikat" (409) od realnego błędu (500).

**`getIOC`** — pobiera IOC + jego wzbogacenia + liczy ryzyko + podpina tagi MITRE:
```go
e.Data = raw
e.Mitre = mitreForSource(e.Source)     // tag ATT&CK po źródle
...
resp := IOCWithEnrichments{IOC: out, Enrichments: enrichments}
resp.Risk = computeRisk(out, enrichments)
writeJSON(w, http.StatusOK, resp)
```

**`listIOCs`** — lista z opcjonalnym filtrem. Sztuczka SQL: `WHERE ($1 = '' OR type = $1)` — puste `$1` przepuszcza wszystko.

**`deleteIOC`** — `DELETE ... WHERE id=$1`, `tag.RowsAffected()==0` → 404, inaczej 204.

**Definicja: `$1, $2` (placeholdery)** — parametry zapytania. `pgx` bezpiecznie podstawia wartości → **ochrona przed SQL injection**. Nigdy nie sklejamy SQL ze stringów.

## 3.4 `sse.go` — realtime (LISTEN/NOTIFY + Server-Sent Events)

**Hub** zarządza otwartymi połączeniami przeglądarek (każde = kanał):
```go
type hub struct { mu sync.Mutex; subs map[chan string]struct{} }
func (h *hub) broadcast(msg string) { ...do każdego subskrybenta wyślij (nieblokująco) }
```
`sync.Mutex` chroni mapę przed równoczesnym dostępem (goroutines).

**`runListener`** — dedykowane połączenie do Postgresa, `LISTEN enrichments`, w pętli `WaitForNotification` → `hub.broadcast(payload)`:
```go
conn.Exec(ctx, "LISTEN enrichments")
for {
    n, _ := conn.WaitForNotification(ctx)   // blokuje aż przyjdzie NOTIFY
    s.hub.broadcast(n.Payload)              // payload = ioc_id
}
```

**`eventsHandler`** (`GET /events`) — endpoint SSE: nagłówki `text/event-stream`, subskrypcja huba, w pętli wypycha zdarzenia + keepalive co 20 s:
```go
w.Header().Set("Content-Type", "text/event-stream")
ch := s.hub.subscribe()
for {
  select {
  case <-ctx.Done(): return               // przeglądarka się rozłączyła
  case iocID := <-ch: fmt.Fprintf(w, "event: enrichment\ndata: %s\n\n", iocID); flusher.Flush()
  case <-keepalive.C: fmt.Fprint(w, ": keepalive\n\n"); flusher.Flush()
  }
}
```

**Definicje:**
- **LISTEN/NOTIFY** — wbudowany w Postgresa mechanizm publikacja/subskrypcja. Worker: `pg_notify('enrichments', ioc_id)`; API nasłuchuje.
- **SSE (Server-Sent Events)** — jednokierunkowy strumień serwer→przeglądarka po jednym długim połączeniu HTTP. Lżejsza kuzynka WebSocketów; tu wystarcza, bo wypychamy tylko w jedną stronę.
- **goroutine** — lekki „wątek" Go. `go f()` uruchamia `f` współbieżnie.
- **channel (`chan`)** — kolejka do komunikacji między goroutines. `select` czeka na wiele kanałów naraz.

## 3.5 `risk.go` — ocena ryzyka

Czysta funkcja `computeRisk(ioc, enrichments) → {score, level, reasons}`. Przechodzi po wzbogaceniach i dodaje punkty za sygnały:
```go
switch e.Source {
case "tor":        if is_tor_exit { score += 40; reasons+=... }
case "whois":      if rejestracja < 90 dni { score += 30 }
case "blocklist":  if on_blocklist { score += 50 }
case "virustotal": add := malicious*10 (max 50); score += add
case "shodan":     add := len(vulns)*10 (max 30)
case "threatfox":  if on_threatfox { score += 50 }
}
// + etykieta źródła zawiera "scan/malware/phish..." → +20
```
Poziom: `<30 low`, `30–59 medium`, `>=60 high`, brak danych → `unknown`. **Wszystko jawne i uzasadnione** (`reasons`) — na rozmowie: „nie ukrywam czarnej skrzynki, każdy punkt ma powód".

## 3.6 `mitre.go` — mapowanie MITRE ATT&CK

Statyczna tabela: źródło/finding → technika ATT&CK:
```go
var mitreBySource = map[string]mitre{
  "crt": {"T1596.003","Search Open Technical Databases: Digital Certificates","Reconnaissance"},
  "tor": {"T1090.003","Proxy: Multi-hop Proxy (Tor)","Command and Control"}, ...
}
func mitreForSource(source string) *mitre { ... }
func mitreForFinding(title string) *mitre { ...dopasowanie po słowie kluczowym w tytule }
```
**Nie odpytujemy API MITRE** — mamy własną mapę. Logika: czynność, którą robimy z IOC, odpowiada technice rozpoznania (Reconnaissance) atakującego. Tag pokazujemy w UI.

## 3.7 `pivots.go` — powiązania (host- i network-level)

`getPivots` (`GET /iocs/{id}/pivots`):
1. Zbiera **IP focal IOC** (własne + `resolved_ips` z dns/cdn).
2. Zaznacza, które IP należą do CDN (`cdnIPSet`) — bo wspólne IP przez CDN to słaby sygnał.
3. Zapytaniem po JSONB znajduje inne IOC dzielące te IP:
```sql
... EXISTS (SELECT 1 FROM jsonb_array_elements_text(e.data->'resolved_ips') AS ip WHERE ip = ANY($2))
```
4. Liczy pewność: `low` jeśli wszystkie wspólne IP to CDN, inaczej `high`.
5. `addASNPivots` — dodatkowo łączy IOC o tym samym ASN (z `geoip`), oznaczone `low` (poziom sieci = szersze/słabsze).

**Na rozmowę:** rozróżniam powiązania **host-level** (wspólne IP) od **network-level** (wspólny ASN), i oceniam ich siłę (CDN/duży ASN = słabe).

## 3.8 `import.go` — masowy import z logów

`POST /import` — regexem wyciąga IP i domeny z wklejonego tekstu, filtruje śmieci (rozszerzenia plików jak `.html`), wstawia `ON CONFLICT DO NOTHING`. Zwraca `{found_ips, found_domains, created, skipped}`.

## 3.9 `stix.go` — eksport STIX 2.1

`GET /export/stix` — buduje **bundle STIX** (standard wymiany CTI, importowalny do MISP). Każdy IOC → obiekt `indicator` z patternem (`[ipv4-addr:value = '...']`). **`uuid5`** = deterministyczny identyfikator (ten sam IOC ma zawsze to samo STIX id → brak duplikatów przy re-imporcie).

## 3.10 `recon.go` — moduł Recon (cele, assety, findings)

Typy `Target`, `Asset`, `Finding` (+ `Mitre`). Endpointy:
- `POST /targets` — dodaj cel (walidacja domeny, `ON CONFLICT`).
- `GET /targets` — lista z licznikami assetów/findings (podzapytania).
- `GET /targets/{id}` — cel + assety + findings (posortowane po severity), findings dostają tag MITRE.
- `DELETE /targets/{id}` — kasuje (kaskadowo assety/findings).

## 3.11 `overview.go` — dashboard „Przegląd"
`GET /overview` — agregaty w SQL: liczniki IOC/celów/assetów, findings pogrupowane po severity, top findings CRITICAL/HIGH (join z targets), IOC z `is_tor_exit=true`.

## 3.12 `watchlist.go` — Śledzenie
`POST /watchlist` (dodaj obiekt), `GET /watchlist` (lista + liczba alertów), `DELETE /watchlist/{id}`, `GET /alerts` (feed alertów, join z watchlist po etykietę).

---

# CZĘŚĆ 4 — WORKERY (Python)

Wszystkie w `worker/`, jeden obraz Docker (`COPY . .`), różne `command` w compose.

## 4.1 `worker.py` — wzbogacanie IOC

**Wzorzec:** lista `ENRICHERS` = krotki `(nazwa, {typy}, funkcja)`. Dodanie źródła = jedna linijka + funkcja.
```python
ENRICHERS = [
  ("dns", {"ip","domain"}, enrich_dns),
  ("whois", {"ip","domain"}, enrich_whois),
  ... ("virustotal", {"ip","domain","hash"}, enrich_virustotal),
]
```

**Pętla** (`process_source`): dla danego źródła znajduje IOC, które **nie mają jeszcze** tego wzbogacenia i je dorabia:
```sql
SELECT i.id,i.type,i.value FROM iocs i
WHERE i.type = ANY(%s)
  AND NOT EXISTS (SELECT 1 FROM enrichments e WHERE e.ioc_id=i.id AND e.source=%s)
LIMIT 10
```
Po wstawieniu wyniku: `SELECT pg_notify('enrichments', ioc_id)` → to zapala SSE w API.

**Definicja: enricher** — funkcja `(ioc_type, value) → dict`. Dict trafia do kolumny `data JSONB`. Każde źródło zwraca swój kształt.

**Ważne mechanizmy w źródłach:**
- **Cache list** (Tor, Cloudflare, CERT/abuse, ThreatFox) — pobieramy dużą listę raz, trzymamy w pamięci z TTL, sprawdzamy członkostwo błyskawicznie. Wzorzec „cache dla wolnych/dużych danych zewnętrznych".
- **RDAP zamiast klasycznego whois** — nowoczesny, JSON-owy następca whois (nie parsujemy tekstu).
- **Rate limiting VirusTotal** — `_vt_last` + `time.sleep`, żeby nie przekroczyć 4/min darmowego limitu.
- **tech** — pobiera HTML + do 3 plików JS (React/Vue często siedzą w bundlu, nie w HTML), dopasowuje sygnatury (CMS, frameworki, hosting, web server, proxy), sonduje GraphQL.

**Klucz API (VirusTotal):** `VT_API_KEY = os.environ.get("VT_API_KEY","")`. Wartość idzie z `.env` (ignorowanego przez git) przez `${VT_API_KEY}` w compose. W kodzie tylko nazwa zmiennej — **sekret nigdy w repo**.

## 4.2 `recon_worker.py` — skan celów

`scan_target`:
1. **Wildcard DNS** — `wildcard_ip(domain)` rozwiązuje losową subdomenę; jeśli odpowiada, domena ma catch-all → brute-force byłby śmieciem.
2. Odkrywa nazwy: crt.sh + apex + brute-force listy popularnych subdomen (ale **odfiltrowuje te, co rozwiązują się na wildcard IP**).
3. Zapisuje assety (`ON CONFLICT DO UPDATE last_seen` = historia).
4. Odpala pasywne checki (`run_checks`) na **apex jako pierwszym** (ma ważny cert) + kilku żywych.
5. `dns_zone_transfer` (AXFR) raz na cel.

**Na rozmowę:** wykrywam wildcard DNS, żeby nie zaśmiecać powierzchni ataku fałszywymi subdomenami — to robią też pro-narzędzia (amass, subfinder).

## 4.3 `checks.py` — silnik pasywnych sprawdzeń

`run_checks(host)` robi serię **pasywnych** GET-ów i zwraca findings:
- odsłonięte `/.env`, `/.git/config`, `/.aws/credentials` (z markerami, żeby nie łapać soft-404),
- panele admin, pliki backup, directory listing, `robots.txt`, Swagger/OpenAPI,
- brakujące nagłówki bezpieczeństwa, wersja `Server`, wewnętrzne IP (nagłówki + body),
- **subdomain takeover** (fingerprinty typu „NoSuchBucket"),
- mining sekretów w JS (AWS/Google/JWT/klucze prywatne),
- `dns_zone_transfer` (dnspython AXFR).

**`baseline`/`soft404`** — najpierw pytamy o losową ścieżkę; jeśli zwraca 200, strona ma catch-all, więc nie ufamy 200 przy sondowaniu (redukcja fałszywych trafień).

**Granica etyczna (WAŻNE na rozmowę):** tylko **pasywne** sprawdzenia (pojedynczy GET „czy X jest odsłonięte"). Aktywne ataki (traversal, JWT, złośliwy input) **świadomie nieautomatyzowane** — to robota manualnego pentestu i wymaga zgody.

## 4.4 `monitor_worker.py` — Śledzenie

Co 5 min dla każdej pozycji watchlisty liczy **sygnaturę** (dla IOC: IP, tor?, blocklist?, threatfox?; dla celu: liczba assetów/findings), porównuje z zapisaną, i przy różnicy tworzy **alert**:
```python
if new.get("tor") and not old.get("tor"): out.append(("high","IP stało się węzłem Tora"))
if "ips" in new and old.get("ips") != new["ips"]: out.append(("medium", f"Zmiana IP: ..."))
```
Reużywa list z `worker.py` przez `from worker import _get_tor_exits, _cert_domains, ...`. **Pierwszy odczyt = baseline (bez alertu)**; alert dopiero przy realnej zmianie.

---

# CZĘŚĆ 5 — FRONTEND (`api/web/index.html`)

Jeden plik: HTML + CSS + JS. Wbudowany w binarkę Go. **Zero zależności zewnętrznych, zero build-stepu.**

## 5.1 Struktura
- Pasek aplikacji + nawigacja (5 zakładek jako `.tab` z `data-view`).
- Pięć `.view` (intel/recon/overview/watch/help); przełączanie pokazuje jeden, chowa resztę.
- `$ = querySelector`, `esc()` = escapowanie HTML (ochrona przed XSS), `api()` = wrapper `fetch` zwracający `{ok, status, body}`.

## 5.2 Kluczowe funkcje JS
- `loadList()` — pobiera `/iocs`, liczy statystyki, filtruje po typie po stronie klienta, renderuje tabelę. **Porównanie sygnatury** (`lastListSig`) → przerysowuje tylko przy zmianie (brak migania).
- `showDetail(id)` — pobiera `/iocs/{id}` + `/iocs/{id}/pivots`, renderuje ryzyko, badge postępu („przetwarzanie… X/Y" — z `EXPECTED_SOURCES`), karty wzbogaceń (`renderEnrichment` — gałąź na każde źródło), pivoty (graf SVG + listy), przyciski Usuń/Śledź.
- `renderEnrichment(e)` — duży `if/else if` po `e.source`; każde źródło ma własny sposób wyświetlenia + tag MITRE + kolor lewej krawędzi karty.
- `buildGraph()` — mały graf SVG pivotów (focal w środku, powiązane wokół).
- Recon: `loadTargets`, `showTarget` (assety, findings z severity, status). Overview: `loadOverview`. Watch: `loadWatch`, `addToWatch`.
- **Realtime:** `EventSource("/events")` — na zdarzenie `enrichment` odświeża listę i otwarte szczegóły. Zapasowy `setInterval` co 15 s (bezpiecznik, gdyby SSE padło).

**Definicja: EventSource** — przeglądarkowe API do odbioru SSE. Само się reconnectuje.

---

# CZĘŚĆ 6 — PRZEPŁYWY END-TO-END

## 6.1 Dodanie IOC → wynik na ekranie
1. UI: `POST /iocs` → `createIOC` waliduje i zapisuje.
2. `worker` (pętla) widzi IOC bez danego źródła → woła enricher → `INSERT enrichment` → `pg_notify('enrichments', ioc_id)`.
3. API (`runListener`, `LISTEN`) dostaje NOTIFY → `hub.broadcast` → wypycha przez `/events` (SSE).
4. Przeglądarka (`EventSource`) dostaje zdarzenie → `showDetail`/`loadList` → nowa karta się pojawia.

## 6.2 Recon
`POST /targets` → `recon-worker` wykrywa wildcard, odkrywa subdomeny, zapisuje assety, odpala checki → findings. UI (zakładka Recon) pokazuje status i wyniki (odświeżanie co 15 s).

## 6.3 Śledzenie
`POST /watchlist` → `monitor-worker` co 5 min liczy sygnaturę, przy zmianie `INSERT alert`. UI (zakładka Śledzenie) pokazuje obserwowane + feed alertów.

---

# CZĘŚĆ 7 — SŁOWNIK POJĘĆ

- **IOC (Indicator of Compromise)** — wskaźnik zagrożenia: IP, domena, hash, URL.
- **Enrichment (wzbogacenie)** — dane dołożone do IOC z zewnętrznego źródła.
- **Pivot** — przeskok z jednego wskaźnika na powiązane przez wspólną cechę (IP, ASN).
- **ASN** — numer systemu autonomicznego = sieć/organizacja w internecie (np. AS13335 = Cloudflare).
- **CDN/WAF** — sieć dostarczania treści / zapora aplikacyjna (Cloudflare, Akamai). Ukrywa origin, dzieli IP między wiele domen.
- **Węzeł wyjściowy Tor** — punkt, przez który anonimowy ruch Tora „wychodzi" do internetu; jego IP nie mówi o sprawcy.
- **RDAP** — nowoczesny, JSON-owy następca whois.
- **Certificate Transparency / crt.sh** — publiczne logi certyfikatów; źródło subdomen.
- **STIX / TAXII** — standardy zapisu i wymiany CTI (STIX = format danych, TAXII = protokół transportu).
- **MITRE ATT&CK** — baza taktyk (po co) i technik (jak) atakujących; wspólny język CTI.
- **SSE / LISTEN-NOTIFY** — mechanizmy realtime (push serwer→przeglądarka, pub/sub w Postgresie).
- **JSONB** — binarny JSON w Postgresie z operatorami zapytań.
- **Modularny monolit** — jeden system z wyraźnymi granicami modułów (nie mikroserwisy).
- **Wildcard DNS** — `*.domena` odpowiada każdemu zapytaniu; psuje brute-force subdomen.
- **Risk score** — ocena 0–100 z jawnych, punktowanych sygnałów.

---

# CZĘŚĆ 8 — PYTANIA ROZMOWOWE + ODPOWIEDZI

**Q: Dlaczego modularny monolit, a nie mikroserwisy?**
A: Przy tej skali i jednoosobowym zespole narzut operacyjny mikroserwisów (sieć, deploy, obserwowalność, spójność danych) się nie opłaca. Wybrałem modularny monolit z wyraźnymi granicami modułów — mogę je rozbić na serwisy później, gdyby zaszła potrzeba. To podejście „MonolithFirst".

**Q: Jak działa realtime bez pollingu?**
A: Worker po zapisie wzbogacenia woła `pg_notify`. API trzyma osobne połączenie z `LISTEN enrichments` i na powiadomienie wypycha zdarzenie do przeglądarki przez SSE. Frontend słucha `EventSource`. Zostawiłem rzadki polling jako bezpiecznik, gdyby SSE padło.

**Q: Czemu wspólne IP nie zawsze znaczy powiązanie?**
A: Jeśli IP należy do CDN (np. Cloudflare), siedzą na nim miliony niepowiązanych domen — więc oznaczam takie pivoty jako „niska pewność". Rozróżniam host-level (wspólne dedykowane IP = mocne) od network-level (wspólny ASN = słabsze).

**Q: Czemu recon jest tylko pasywny?**
A: Bo narzędzie może wskazać dowolną domenę. Aktywne ataki (traversal, JWT, złośliwy input) są nielegalne bez zgody i to robota manualnego pentestu. Robię tylko pasywne sprawdzenia „czy X jest odsłonięte" + bramkę „skanuj tylko to, na co masz prawo".

**Q: Jak liczysz ryzyko?**
A: Jawna, punktowana heurystyka z sygnałów (Tor, świeża rejestracja, blacklista, VirusTotal, Shodan CVE, ThreatFox). Każdy punkt ma powód pokazany w UI — świadomie nie robię czarnej skrzynki.

**Q: Jak trzymasz sekrety poza repo?**
A: Klucz API tylko w `.env` (w `.gitignore`), przekazywany przez `${VT_API_KEY}` w compose, czytany `os.environ` w kodzie. W repo jest tylko nazwa zmiennej i `.env.example` z pustą wartością. Zweryfikowałem, że klucz nie występuje nigdzie poza `.env`.

**Q: Czemu geolokalizacja IP nie wystarcza do atrybucji?**
A: Bo IP może być węzłem Tora, proxy albo CDN. U mnie widać to wprost — enricher `tor`, `cdn`, Shodan i whois niezależnie to potwierdzają. Wartość CTI to korelacja wielu źródeł, nie jeden sygnał.

**Q: Jak dodałbyś nowe źródło wzbogacenia?**
A: Napisać funkcję `(ioc_type, value) → dict` i dodać jedną krotkę do listy `ENRICHERS`. Reszta (szukanie IOC bez tego źródła, zapis, NOTIFY, render) działa automatycznie. To celowo rozszerzalny wzorzec.

**Q: Największe ograniczenia projektu?**
A: Szeroki, ale miejscami płytki (heurystyki, cienkie testy). Nie jest produkcyjny (brak auth, paginacji, rate-limitingu API). Zależy od flaky serwisów zewnętrznych. To świadome kompromisy pod cel: portfolio + nauka + praktyczne narzędzie.
