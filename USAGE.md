# TI Aggregator — instrukcja obsługi (krok po kroku)

Ten dokument tłumaczy, jak uruchomić i używać aplikacji — od zera, bez zakładania wiedzy.

---

## 1. Uruchomienie

1. Włącz **Docker Desktop** (poczekaj, aż ikonka pokaże „Engine running").
2. W terminalu wejdź do folderu projektu i odpal wszystko:
   ```
   cd ~/gitproject
   docker compose up -d --build
   ```
   - `up` — uruchom usługi (baza, API+frontend, worker, Adminer)
   - `-d` — w tle
   - `--build` — przebuduj obrazy, jeśli zmienił się kod
3. Sprawdź, że wszystko stoi:
   ```
   docker compose ps
   ```
   Powinny być cztery usługi: `db`, `api`, `worker`, `adminer`.

Otwórz w przeglądarce: **http://localhost:8080/**

---

## 2. Co widzisz na ekranie

Dashboard ma **dwa panele**:

- **Lewy — „Wskaźniki (IOC)":** formularz dodawania, filtry i lista wszystkich wskaźników.
- **Prawy — „Szczegóły":** po kliknięciu wskaźnika pokazuje jego wzbogacenia (dane dorobione automatycznie).

IOC (Indicator of Compromise) = wskaźnik zagrożenia: adres IP, domena, hash pliku albo URL.

---

## 3. Dodawanie wskaźnika

W formularzu na górze lewego panelu:

1. **Typ** — wybierz z listy: `ip`, `domain`, `hash` albo `url`.
2. **Wartość** — wpisz konkret, np. `185.220.101.5` (dla ip) albo `example.com` (dla domain).
3. **Źródło** — opcjonalnie, skąd masz ten wskaźnik (np. `wordpress-scan`, `logi klienta`).
4. Kliknij **Dodaj**.

Po dodaniu:
- pojawi się zielony komunikat `dodano ✓`, a wskaźnik trafi na listę,
- jeśli taki wskaźnik już istnieje, zobaczysz komunikat `taki IOC już istnieje` (system nie dubluje danych),
- jeśli wpiszesz np. `ip` z niepoprawnym adresem, dostaniesz komunikat walidacji.

---

## 4. Filtrowanie listy

Pod formularzem są przyciski: **wszystkie / ip / domain**. Kliknięcie zawęża listę do danego typu. „wszystkie" pokazuje komplet.

---

## 5. Podgląd szczegółów i wzbogaceń

Kliknij dowolny wiersz na liście → prawy panel pokaże szczegóły wskaźnika i jego **wzbogacenia** (enrichments). Każde wzbogacenie to osobna karta z etykietą źródła:

- **dns** — wynik DNS:
  - dla domeny: `IP:` lista adresów, na które wskazuje,
  - dla IP: `host:` nazwa hosta (reverse DNS), albo błąd, jeśli brak wpisu (to normalne).
- **whois** — dane RDAP (nowoczesny whois): `kraj`, `nazwa`, `handle`, `domena`. Pod spodem rozwijane **„surowy RDAP"** — pełna odpowiedź, jeśli chcesz szczegóły.
- **tor** — czy IP to **węzeł wyjściowy Tora**:
  - czerwony badge **WĘZEŁ TOR** → tak (uwaga: geolokalizacja IP nic nie mówi o sprawcy),
  - zielony **nie-Tor** → nie.
- **cdn** (dla domen) — wykrywa CDN/WAF (Cloudflare, Akamai, Fastly, CloudFront):
  - pomarańczowy badge z nazwą dostawcy (np. **CLOUDFLARE**, **AKAMAI**) → domena jest za CDN/WAF,
  - `IP:` adresy, na które wskazuje domena,
  - **możliwy origin (heurystyka)** → kandydaci na prawdziwy adres serwera, znalezieni przez sprawdzenie typowych subdomen (`direct.`, `ftp.`, `cpanel.`…). **Uwaga: NIEPEWNE** — to tylko wskazówki, wymagają weryfikacji. CDN celowo ukrywa origin.
- **crt** (dla domen) — **crt.sh / Certificate Transparency**: subdomeny znalezione w publicznych certyfikatach. Rozwiń „pokaż subdomeny", żeby zobaczyć listę. Świetne do mapowania powierzchni ataku.
- **tech** (dla domen/URL) — lekki fingerprint stacku (mini-Wappalyzer): `server`, `x-powered-by`, wykryte technologie z HTML (WordPress, Next.js, Svelte…). **Orientacyjnie**, nie pełny Wappalyzer.

---

## 6. Jak to działa „w tle" (ważne)

Gdy dodajesz wskaźnik, API tylko go **zapisuje** i od razu odpowiada. Wzbogaceniami zajmuje się **osobny proces (worker)**, który co kilka sekund sprawdza bazę i dorabia dane (DNS, whois, Tor, Cloudflare).

Dlatego: **tuż po dodaniu** szczegóły mogą pokazać „Brak wzbogaceń jeszcze". To normalne — poczekaj kilka sekund i **kliknij wskaźnik ponownie**, żeby odświeżyć. Wzbogacenia dojdą stopniowo.

Podgląd pracy workera na żywo:
```
docker compose logs -f worker
```
(wyjście: `Ctrl+C`)

---

## 7. Podgląd bazy danych (Adminer)

Jeśli chcesz zajrzeć wprost do bazy: **http://localhost:8081**
- System: **PostgreSQL**, Serwer: **db**, Użytkownik: **ti**, Hasło: **ti**, Baza: **ti**
- tabela `iocs` — wskaźniki, tabela `enrichments` — wzbogacenia.

---

## 8. Zatrzymanie i restart

- Zatrzymać (zachowując dane):
  ```
  docker compose down
  ```
- Zatrzymać i **skasować dane** (czysty start):
  ```
  docker compose down -v
  ```
- Po zmianie kodu — przebuduj:
  ```
  docker compose up -d --build
  ```

---

## 9. Gdy coś nie działa

- **Strona się nie otwiera** → sprawdź `docker compose ps`; jeśli `api` nie stoi, zobacz logi: `docker compose logs api`.
- **Lista pusta** → dodaj wskaźnik, albo baza została wyczyszczona (`down -v`).
- **Brak wzbogaceń** → worker jeszcze nie zdążył; poczekaj i kliknij ponownie. Sprawdź `docker compose logs worker`.
- **`docker` nie odpowiada** → Docker Desktop nie jest uruchomiony.
