# TI Aggregator

Threat-Intelligence aggregator — zbiera wskaźniki zagrożeń (IOC), wzbogaca je z publicznych źródeł, pozwala pivotować na powiązania, eksportuje w STIX/TAXII.

Cel: **portfolio + nauka backendu + własny silnik pod bug bounty.**

## Struktura (rośnie krok po kroku)
```
gitproject/
├── docker-compose.yml   # Postgres + Adminer (panel do bazy)
├── .env.example         # wzór konfiguracji (skopiuj do .env)
├── api/                 # backend w Go  (Krok 2)
└── migrations/          # pliki SQL tworzące tabele  (Krok 3)
```

## Jak odpalić bazę (Krok 1 — już działa)
1. Zainstaluj Docker Desktop, jeśli nie masz.
2. W folderze projektu:
   ```
   docker compose up -d db adminer
   ```
3. Sprawdź, że baza żyje — otwórz w przeglądarce **http://localhost:8081**
   (System: PostgreSQL, Serwer: `db`, Użytkownik: `ti`, Hasło: `ti`, Baza: `ti`).

To na razie tyle — backend dochodzi w Kroku 2.
