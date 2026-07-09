import os
import time
import socket

import psycopg
from psycopg.types.json import Json
import requests

DATABASE_URL = os.environ["DATABASE_URL"]
POLL_SECONDS = 5


# ── ŹRÓDŁA WZBOGACEŃ ───────────────────────────────────────────────────────

def enrich_dns(ioc_type: str, value: str) -> dict:
    """DNS: domena -> IP, IP -> nazwa hosta."""
    result = {}
    try:
        if ioc_type == "domain":
            infos = socket.getaddrinfo(value, None)
            result["resolved_ips"] = sorted({i[4][0] for i in infos})
        elif ioc_type == "ip":
            hostname, aliases, _ = socket.gethostbyaddr(value)
            result["hostname"] = hostname
            result["aliases"] = aliases
    except Exception as e:
        result["error"] = str(e)
    return result


def _rdap_highlights(data: dict) -> dict:
    """Wyciąga kilka najważniejszych pól z RDAP (całość i tak zapisujemy w 'raw')."""
    h = {}
    for k in ("handle", "ldhName", "name", "country", "startAddress", "endAddress", "type"):
        if data.get(k) is not None:
            h[k] = data[k]
    if data.get("status"):
        h["status"] = data["status"]
    return h


def enrich_whois(ioc_type: str, value: str) -> dict:
    """whois przez RDAP (nowoczesny, JSON-owy następca whois)."""
    if ioc_type == "domain":
        url = f"https://rdap.org/domain/{value}"
    elif ioc_type == "ip":
        url = f"https://rdap.org/ip/{value}"
    else:
        return {"error": "typ nieobsługiwany przez whois"}
    try:
        resp = requests.get(url, timeout=10, headers={"Accept": "application/rdap+json"})
        if resp.status_code == 404:
            return {"error": "brak danych RDAP (404)"}
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        return {"error": str(e)}
    # Zapisujemy skrót (highlights) + surowy RDAP (raw) jako źródło prawdy.
    return {"highlights": _rdap_highlights(data), "raw": data}


# Cache listy węzłów wyjściowych Tora — pobieramy raz, trzymamy w pamięci.
TOR_LIST_URL = "https://check.torproject.org/torbulkexitlist"
TOR_TTL = 3600  # odśwież listę raz na godzinę (w sekundach)
_tor_cache = {"ips": set(), "fetched_at": 0.0}


def _get_tor_exits() -> set:
    """Zwraca zbiór IP węzłów wyjściowych Tora. Pobiera z sieci tylko gdy cache jest stary."""
    now = time.time()
    if not _tor_cache["ips"] or (now - _tor_cache["fetched_at"] > TOR_TTL):
        resp = requests.get(TOR_LIST_URL, timeout=15)
        resp.raise_for_status()
        # Lista to zwykły tekst: jedno IP na linię (pomijamy komentarze i puste).
        ips = {
            line.strip()
            for line in resp.text.splitlines()
            if line.strip() and not line.startswith("#")
        }
        _tor_cache["ips"] = ips
        _tor_cache["fetched_at"] = now
        print(f"[worker] pobrano listę Tor exit ({len(ips)} IP)", flush=True)
    return _tor_cache["ips"]


def enrich_tor(ioc_type: str, value: str) -> dict:
    """Sprawdza, czy IP jest znanym węzłem wyjściowym Tora."""
    if ioc_type != "ip":
        return {"error": "tor: dotyczy tylko IP"}
    try:
        exits = _get_tor_exits()
    except Exception as e:
        return {"error": str(e)}
    return {
        "is_tor_exit": value in exits,
        "source_list": "Tor Project bulk exit list",
    }


# Lista źródeł: (nazwa, jakich typów IOC dotyczy, funkcja wzbogacająca).
# Dodanie kolejnego źródła (np. VirusTotal) = jedna linijka tutaj + funkcja wyżej.
ENRICHERS = [
    ("dns", {"ip", "domain"}, enrich_dns),
    ("whois", {"ip", "domain"}, enrich_whois),
    ("tor", {"ip"}, enrich_tor),
]


# ── LOGIKA WORKERA ─────────────────────────────────────────────────────────

def process_source(conn, source: str, types: set, fn) -> int:
    """Znajduje IOC bez danego wzbogacenia, dorabia je i zapisuje. Zwraca ile obrobił."""
    with conn.cursor() as cur:
        # type = ANY(%s): psycopg zamienia listę Pythona na tablicę Postgresa.
        cur.execute(
            """
            SELECT i.id, i.type, i.value
            FROM iocs i
            WHERE i.type = ANY(%s)
              AND NOT EXISTS (
                  SELECT 1 FROM enrichments e
                  WHERE e.ioc_id = i.id AND e.source = %s
              )
            LIMIT 10
            """,
            (list(types), source),
        )
        rows = cur.fetchall()

        for ioc_id, ioc_type, value in rows:
            data = fn(ioc_type, value)
            cur.execute(
                "INSERT INTO enrichments (ioc_id, source, data) VALUES (%s, %s, %s)",
                (ioc_id, source, Json(data)),
            )
            print(f"[worker] {source}: IOC {ioc_id} ({value})", flush=True)
            time.sleep(0.5)  # grzecznie wobec zewnętrznych serwerów

        conn.commit()
        return len(rows)


def process_once(conn) -> int:
    total = 0
    for source, types, fn in ENRICHERS:
        total += process_source(conn, source, types, fn)
    return total


def main():
    print("[worker] start", flush=True)
    while True:
        try:
            with psycopg.connect(DATABASE_URL) as conn:
                print("[worker] połączono z bazą, nasłuchuję nowych IOC", flush=True)
                while True:
                    n = process_once(conn)
                    if n == 0:
                        time.sleep(POLL_SECONDS)
        except Exception as e:
            print(f"[worker] błąd: {e}; ponawiam za 3s", flush=True)
            time.sleep(3)


if __name__ == "__main__":
    main()
