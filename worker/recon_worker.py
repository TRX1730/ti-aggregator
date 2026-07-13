import os
import time
import socket
import random
import string

import psycopg
import requests

from checks import run_checks, dns_zone_transfer

DATABASE_URL = os.environ["DATABASE_URL"]
POLL_SECONDS = 10
RESCAN_HOURS = 24
MAX_CHECK_HOSTS = 12

SUBDOMAIN_WORDLIST = [
    "www", "api", "dev", "staging", "test", "admin", "mail", "webmail", "smtp",
    "ns1", "ns2", "vpn", "portal", "app", "apps", "cdn", "static", "assets",
    "blog", "shop", "store", "secure", "login", "auth", "dashboard", "panel",
    "cpanel", "git", "gitlab", "jenkins", "ci", "docs", "support", "status",
    "grafana", "kibana", "db", "backup", "beta", "demo", "mobile", "internal",
    "intranet", "remote", "gateway", "proxy", "files", "ftp",
]


def crtsh_subdomains(domain: str) -> list:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=25, headers={"User-Agent": "ti-platform-recon"})
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        return []
    subs = set()
    for entry in data:
        for name in str(entry.get("name_value", "")).splitlines():
            name = name.strip().lstrip("*.").lower()
            if name.endswith(domain):
                subs.add(name)
    return sorted(subs)


def resolve(host: str):
    try:
        return socket.getaddrinfo(host, None)[0][4][0]
    except Exception:
        return None


def wildcard_ip(domain: str):
    rnd = "".join(random.choices(string.ascii_lowercase + string.digits, k=14))
    return resolve(f"{rnd}.{domain}")


def scan_target(conn, target_id: int, domain: str):
    wc = wildcard_ip(domain)
    discovered = {domain: resolve(domain)}
    for sub in crtsh_subdomains(domain):
        if sub not in discovered:
            discovered[sub] = resolve(sub)
    for w in SUBDOMAIN_WORDLIST:
        host = f"{w}.{domain}"
        if host in discovered:
            continue
        ip = resolve(host)
        if ip and (wc is None or ip != wc):
            discovered[host] = ip

    resolvable = []
    with conn.cursor() as cur:
        for name, ip in sorted(discovered.items()):
            cur.execute(
                """
                INSERT INTO assets (target_id, type, value, resolved_ip)
                VALUES (%s, 'subdomain', %s, %s)
                ON CONFLICT (target_id, value)
                DO UPDATE SET last_seen = now(), resolved_ip = EXCLUDED.resolved_ip
                """,
                (target_id, name, ip),
            )
            if ip:
                resolvable.append(name)
        if wc:
            cur.execute(
                """
                INSERT INTO findings (target_id, asset, severity, title, detail)
                VALUES (%s, %s, 'low', 'Wildcard DNS', %s)
                ON CONFLICT (target_id, asset, title) DO NOTHING
                """,
                (target_id, domain, f"*.{domain} -> {wc}; enumeracja brute-force ograniczona"),
            )
        cur.execute("UPDATE targets SET last_scanned_at = now() WHERE id = %s", (target_id,))
    conn.commit()
    print(f"[recon] target {target_id} ({domain}): {len(discovered)} assetów, {len(resolvable)} żywych, wildcard={wc}", flush=True)

    check_hosts = [domain] + sorted(h for h in resolvable if h != domain)
    for host in check_hosts[:MAX_CHECK_HOSTS]:
        for f in run_checks(host):
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO findings (target_id, asset, severity, title, detail)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (target_id, asset, title) DO NOTHING
                    """,
                    (target_id, host, f["severity"], f["title"], f["detail"]),
                )
            conn.commit()
        time.sleep(0.3)

    for f in dns_zone_transfer(domain):
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO findings (target_id, asset, severity, title, detail)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (target_id, asset, title) DO NOTHING
                """,
                (target_id, domain, f["severity"], f["title"], f["detail"]),
            )
        conn.commit()

    print(f"[recon] checks zakończone dla {target_id} ({domain})", flush=True)


def process_once(conn) -> int:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, domain FROM targets
            WHERE last_scanned_at IS NULL
               OR last_scanned_at < now() - make_interval(hours => %s)
            ORDER BY last_scanned_at NULLS FIRST
            LIMIT 3
            """,
            (RESCAN_HOURS,),
        )
        rows = cur.fetchall()
    for target_id, domain in rows:
        with conn.cursor() as cur:
            cur.execute("UPDATE targets SET status = 'scanning' WHERE id = %s", (target_id,))
        conn.commit()
        scan_target(conn, target_id, domain)
        with conn.cursor() as cur:
            cur.execute("UPDATE targets SET status = 'done' WHERE id = %s", (target_id,))
        conn.commit()
    return len(rows)


def main():
    print("[recon] start", flush=True)
    while True:
        try:
            with psycopg.connect(DATABASE_URL) as conn:
                print("[recon] połączono z bazą, nasłuchuję nowych celów", flush=True)
                while True:
                    n = process_once(conn)
                    if n == 0:
                        time.sleep(POLL_SECONDS)
        except Exception as e:
            print(f"[recon] błąd: {e}; ponawiam za 3s", flush=True)
            time.sleep(3)


if __name__ == "__main__":
    main()
