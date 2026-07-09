import os
import time
import socket

import psycopg
from psycopg.types.json import Json

# Adres bazy — ta sama zmienna, co dla API (ustawiona w docker-compose).
DATABASE_URL = os.environ["DATABASE_URL"]

# Co ile sekund sprawdzać, czy pojawiły się nowe IOC do wzbogacenia.
POLL_SECONDS = 5


def enrich_dns(ioc_type: str, value: str) -> dict:
    """Zwraca dane DNS dla danego IOC jako słownik (trafi do kolumny JSONB)."""
    result = {}
    try:
        if ioc_type == "domain":
            # Domena -> lista adresów IP, na które wskazuje.
            infos = socket.getaddrinfo(value, None)
            ips = sorted({info[4][0] for info in infos})
            result["resolved_ips"] = ips
        elif ioc_type == "ip":
            # IP -> nazwa hosta (reverse DNS / PTR).
            hostname, aliases, _ = socket.gethostbyaddr(value)
            result["hostname"] = hostname
            result["aliases"] = aliases
    except Exception as e:
        # Błąd (np. domena nie istnieje) też jest wynikiem — zapisujemy go.
        result["error"] = str(e)
    return result


def process_once(conn) -> int:
    """Znajduje IOC bez wzbogacenia DNS, wzbogaca je i zapisuje. Zwraca ile obrobił."""
    with conn.cursor() as cur:
        # Bierzemy IOC typu ip/domain, które NIE mają jeszcze wzbogacenia 'dns'.
        cur.execute(
            """
            SELECT i.id, i.type, i.value
            FROM iocs i
            WHERE i.type IN ('ip', 'domain')
              AND NOT EXISTS (
                  SELECT 1 FROM enrichments e
                  WHERE e.ioc_id = i.id AND e.source = 'dns'
              )
            LIMIT 10
            """
        )
        rows = cur.fetchall()

        for ioc_id, ioc_type, value in rows:
            data = enrich_dns(ioc_type, value)
            # Json(...) mówi psycopg: zapisz ten słownik jako JSONB.
            cur.execute(
                "INSERT INTO enrichments (ioc_id, source, data) VALUES (%s, 'dns', %s)",
                (ioc_id, Json(data)),
            )
            print(f"[worker] wzbogacono IOC {ioc_id} ({value}) -> {data}", flush=True)

        conn.commit()
        return len(rows)


def main():
    print("[worker] start", flush=True)
    # Pętla zewnętrzna: gdyby baza padła/nie wstała jeszcze, próbujemy dalej.
    while True:
        try:
            with psycopg.connect(DATABASE_URL) as conn:
                print("[worker] połączono z bazą, nasłuchuję nowych IOC", flush=True)
                # Pętla wewnętrzna: obrabiaj, a gdy nic nie ma — poczekaj i sprawdź znowu.
                while True:
                    n = process_once(conn)
                    if n == 0:
                        time.sleep(POLL_SECONDS)
        except Exception as e:
            print(f"[worker] błąd: {e}; ponawiam za 3s", flush=True)
            time.sleep(3)


if __name__ == "__main__":
    main()
