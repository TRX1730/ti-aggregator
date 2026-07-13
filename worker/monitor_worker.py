import os
import time
import socket

import psycopg
from psycopg.types.json import Json

from worker import _get_tor_exits, _cert_domains, _urlhaus_domains, _feodo_ips, _threatfox_map

DATABASE_URL = os.environ["DATABASE_URL"]
INTERVAL = 300


def resolve_all(host: str) -> list:
    try:
        return sorted({i[4][0] for i in socket.getaddrinfo(host, None)})
    except Exception:
        return []


def ioc_signature(ioc_type: str, value: str) -> dict:
    sig = {}
    if ioc_type == "domain":
        sig["ips"] = resolve_all(value)
    elif ioc_type == "ip":
        sig["ips"] = [value]
    try:
        if ioc_type == "ip":
            sig["tor"] = value in _get_tor_exits()
    except Exception:
        pass
    try:
        if ioc_type == "domain":
            sig["blocklist"] = (value.lower() in _cert_domains()) or (value.lower() in _urlhaus_domains())
        elif ioc_type == "ip":
            sig["blocklist"] = value in _feodo_ips()
    except Exception:
        pass
    try:
        sig["threatfox"] = value.lower() in _threatfox_map()
    except Exception:
        pass
    return sig


def diff_alerts(old, new) -> list:
    out = []
    if not old:
        return out
    if "ips" in new and old.get("ips") is not None and old.get("ips") != new["ips"]:
        out.append(("medium", f"Zmiana IP: {old.get('ips')} -> {new['ips']}"))
    if new.get("tor") and not old.get("tor"):
        out.append(("high", "IP stało się węzłem wyjściowym Tora"))
    if new.get("blocklist") and not old.get("blocklist"):
        out.append(("high", "Pojawił się na blackliście (CERT/abuse.ch)"))
    if new.get("threatfox") and not old.get("threatfox"):
        out.append(("high", "Pojawił się na feedzie ThreatFox (malware)"))
    return out


def check_ioc(conn, wid, ref_id, old_sig):
    with conn.cursor() as cur:
        cur.execute("SELECT type, value FROM iocs WHERE id=%s", (ref_id,))
        row = cur.fetchone()
    if not row:
        return
    ioc_type, value = row
    new_sig = ioc_signature(ioc_type, value)
    with conn.cursor() as cur:
        for sev, msg in diff_alerts(old_sig, new_sig):
            cur.execute("INSERT INTO alerts (watchlist_id, severity, message) VALUES (%s, %s, %s)",
                        (wid, sev, msg))
        cur.execute("UPDATE watchlist SET sig=%s, last_checked=now() WHERE id=%s", (Json(new_sig), wid))
    conn.commit()


def check_target(conn, wid, ref_id, old_sig):
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM assets WHERE target_id=%s", (ref_id,))
        assets = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM findings WHERE target_id=%s", (ref_id,))
        findings = cur.fetchone()[0]
    new_sig = {"assets": assets, "findings": findings}
    with conn.cursor() as cur:
        if old_sig:
            if assets > old_sig.get("assets", 0):
                cur.execute("INSERT INTO alerts (watchlist_id, severity, message) VALUES (%s, 'medium', %s)",
                            (wid, f"Nowe assety: +{assets - old_sig.get('assets', 0)}"))
            if findings > old_sig.get("findings", 0):
                cur.execute("INSERT INTO alerts (watchlist_id, severity, message) VALUES (%s, 'medium', %s)",
                            (wid, f"Nowe findings: +{findings - old_sig.get('findings', 0)}"))
        cur.execute("UPDATE watchlist SET sig=%s, last_checked=now() WHERE id=%s", (Json(new_sig), wid))
    conn.commit()


def process(conn):
    with conn.cursor() as cur:
        cur.execute("SELECT id, kind, ref_id, sig FROM watchlist ORDER BY id")
        rows = cur.fetchall()
    for wid, kind, ref_id, sig in rows:
        try:
            if kind == "ioc":
                check_ioc(conn, wid, ref_id, sig)
            elif kind == "target":
                check_target(conn, wid, ref_id, sig)
        except Exception as e:
            print(f"[monitor] błąd {wid}: {e}", flush=True)


def main():
    print("[monitor] start", flush=True)
    while True:
        try:
            with psycopg.connect(DATABASE_URL) as conn:
                print("[monitor] połączono, monitoruję watchlistę", flush=True)
                while True:
                    process(conn)
                    time.sleep(INTERVAL)
        except Exception as e:
            print(f"[monitor] błąd: {e}; ponawiam za 5s", flush=True)
            time.sleep(5)


if __name__ == "__main__":
    main()
