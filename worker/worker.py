import os
import time
import socket
import ipaddress

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


# ── Wykrywanie CDN/WAF (Cloudflare, Akamai, Fastly, CloudFront) + origin ───
CF_URLS = ["https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"]
CF_TTL = 24 * 3600  # zakresy Cloudflare zmieniają się rzadko — odśwież raz na dobę
_cf_cache = {"nets": [], "fetched_at": 0.0}

# Dostawcy bez publicznej listy IP — wykrywani po wzorcach w reverse DNS.
CDN_HOST_PATTERNS = {
    "akamai": ["akamai", "akamaitechnologies", "akamaiedge", "edgekey", "edgesuite"],
    "fastly": ["fastly"],
    "cloudfront": ["cloudfront"],
}

# Typowe subdomeny, które czasem wskazują wprost na origin (omijają CDN).
ORIGIN_PREFIXES = ["direct", "origin", "ftp", "cpanel", "webmail", "mail", "server", "vpn", "dev"]


def _get_cloudflare_nets() -> list:
    """Zwraca listę zakresów IP Cloudflare. Pobiera z sieci tylko gdy cache stary."""
    now = time.time()
    if not _cf_cache["nets"] or (now - _cf_cache["fetched_at"] > CF_TTL):
        nets = []
        for url in CF_URLS:
            resp = requests.get(url, timeout=15)
            resp.raise_for_status()
            for line in resp.text.splitlines():
                line = line.strip()
                if line:
                    nets.append(ipaddress.ip_network(line))
        _cf_cache["nets"] = nets
        _cf_cache["fetched_at"] = now
        print(f"[worker] pobrano zakresy Cloudflare ({len(nets)} sieci)", flush=True)
    return _cf_cache["nets"]


def _ip_in_nets(ip: str, nets: list) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr.version == n.version and addr in n for n in nets)


def _resolve(host: str) -> list:
    try:
        return sorted({i[4][0] for i in socket.getaddrinfo(host, None)})
    except Exception:
        return []


def _reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0].lower()
    except Exception:
        return ""


def _detect_provider(ips: list, cf_nets: list):
    """Zwraca nazwę dostawcy CDN/WAF dla listy IP, albo None."""
    # Cloudflare — po zakresach IP (pewne).
    if any(_ip_in_nets(ip, cf_nets) for ip in ips):
        return "cloudflare"
    # Reszta — po reverse DNS (heurystyka).
    for ip in ips:
        host = _reverse_dns(ip)
        if host:
            for provider, needles in CDN_HOST_PATTERNS.items():
                if any(n in host for n in needles):
                    return provider
    return None


def enrich_cdn(ioc_type: str, value: str) -> dict:
    """Wykrywa CDN/WAF domeny (Cloudflare/Akamai/Fastly/CloudFront) i heurystycznie szuka origin."""
    if ioc_type != "domain":
        return {"error": "cdn: dotyczy tylko domen"}
    try:
        cf_nets = _get_cloudflare_nets()
    except Exception as e:
        return {"error": str(e)}

    ips = _resolve(value)
    if not ips:
        return {"error": "nie udało się rozwiązać domeny"}

    provider = _detect_provider(ips, cf_nets)
    result = {"resolved_ips": ips, "behind_cdn": provider is not None, "provider": provider}

    if provider:
        candidates = []
        for prefix in ORIGIN_PREFIXES:
            host = f"{prefix}.{value}"
            # kandydat = subdomena wskazująca poza jakikolwiek wykryty CDN
            non_cdn = [ip for ip in _resolve(host) if _detect_provider([ip], cf_nets) is None]
            if non_cdn:
                candidates.append({"subdomain": host, "ips": non_cdn})
        result["origin_candidates"] = candidates
        result["origin_note"] = "Kandydaci na origin z heurystyki. NIEPEWNE — wymaga weryfikacji."

    return result


def enrich_crtsh(ioc_type: str, value: str) -> dict:
    """crt.sh (Certificate Transparency): subdomeny z wystawionych certyfikatów."""
    if ioc_type != "domain":
        return {"error": "crt.sh: dotyczy tylko domen"}
    url = f"https://crt.sh/?q=%25.{value}&output=json"
    try:
        resp = requests.get(url, timeout=25, headers={"User-Agent": "ti-aggregator"})
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        return {"error": str(e)}
    subs = set()
    for entry in data:
        for name in str(entry.get("name_value", "")).splitlines():
            name = name.strip().lstrip("*.").lower()
            if name.endswith(value):
                subs.add(name)
    subs = sorted(subs)
    return {"count": len(subs), "subdomains": subs[:200]}  # limit, żeby nie przesadzić


# Sygnatury w HTML, pogrupowane w kategorie.
TECH_SIGNATURES = {
    "cms": {
        "WordPress": ["wp-content", "wp-includes"],
        "Drupal": ["/sites/default/", "drupal-settings-json", "drupal.js"],
        "Joomla": ["/media/jui/", "joomla"],
        "Ghost": ["/ghost/", "ghost-"],
        "Shopify": ["cdn.shopify.com"],
        "Wix": ["static.wixstatic.com", "wix.com"],
        "Squarespace": ["squarespace"],
        "Webflow": ["webflow"],
    },
    "framework": {
        "React": ["data-reactroot", "__react", "react.production"],
        "Vue.js": ["__vue__", "data-v-", "vue.js"],
        "Svelte": ["svelte-"],
        "Angular": ["ng-version", "angular.js"],
        "Next.js": ["/_next/", "__next_data__"],
        "Nuxt.js": ["/_nuxt/", "__nuxt"],
        "Gatsby": ["___gatsby"],
    },
    "js_lib": {
        "jQuery": ["jquery"],
        "Bootstrap": ["bootstrap.min"],
        "Tailwind CSS": ["tailwind"],
    },
    "analytics": {
        "Google Analytics": ["google-analytics.com", "googletagmanager.com", "gtag("],
        "Meta Pixel": ["connect.facebook.net", "fbq("],
        "Hotjar": ["hotjar"],
        "Segment": ["cdn.segment.com"],
        "Plausible": ["plausible.io"],
        "Matomo": ["matomo"],
    },
    "external": {
        "Stripe": ["js.stripe.com"],
        "PayPal": ["paypal.com/sdk", "paypalobjects"],
        "Sentry": ["sentry-cdn", "@sentry"],
        "Intercom": ["intercom"],
        "HubSpot": ["hs-scripts", "hubspot"],
        "reCAPTCHA": ["recaptcha"],
    },
}

# Backend rozpoznawany po nazwach ciasteczek sesyjnych.
COOKIE_SIGNATURES = {
    "phpsessid": "PHP",
    "laravel_session": "Laravel",
    "connect.sid": "Express / Node.js",
    "csrftoken": "Django",
    "jsessionid": "Java (JSP/Servlet)",
    "ci_session": "CodeIgniter",
    "asp.net": "ASP.NET",
}

# Backend rozpoznawany po nagłówkach serwera (Server / X-Powered-By).
SERVER_BACKEND = {
    "express": "Express / Node.js",
    "gunicorn": "Python (Gunicorn)",
    "uvicorn": "Python (ASGI)",
    "werkzeug": "Python (Flask)",
    "php": "PHP",
    "tomcat": "Java (Tomcat)",
    "jetty": "Java (Jetty)",
    "glassfish": "Java (GlassFish)",
    "kestrel": ".NET (Kestrel)",
    "asp.net": "ASP.NET",
    "golang": "Go",
    "go-http": "Go",
    "cowboy": "Elixir/Erlang (Cowboy)",
    "puma": "Ruby (Puma)",
    "passenger": "Ruby (Passenger)",
}

GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql"]


def _detect_graphql(base: str):
    """Aktywnie sonduje typowe ścieżki GraphQL minimalną introspekcją."""
    for path in GRAPHQL_PATHS:
        try:
            r = requests.post(
                base.rstrip("/") + path,
                json={"query": "{__typename}"},
                timeout=8,
                headers={"User-Agent": "ti-aggregator"},
            )
            if "application/json" in r.headers.get("content-type", "").lower():
                j = r.json()
                if isinstance(j, dict) and ("data" in j or "errors" in j):
                    return path
        except Exception:
            continue
    return None


def enrich_tech(ioc_type: str, value: str) -> dict:
    """Fingerprint stacku: CMS, frameworki, biblioteki, analityka, usługi, backend, API/GraphQL."""
    if ioc_type not in ("domain", "url"):
        return {"error": "tech: dotyczy domen/URL"}
    url = value if value.startswith("http") else f"https://{value}"
    try:
        resp = requests.get(
            url, timeout=15,
            headers={"User-Agent": "Mozilla/5.0 ti-aggregator"},
            allow_redirects=True,
        )
    except Exception as e:
        return {"error": str(e)}

    h = {k.lower(): v for k, v in resp.headers.items()}
    body = resp.text[:400000].lower()
    result = {"status_code": resp.status_code, "final_url": str(resp.url)}

    # Nagłówki serwera.
    server_info = {}
    for hk in ("server", "x-powered-by", "x-generator", "x-aspnet-version", "via"):
        if hk in h:
            server_info[hk] = h[hk]
    if server_info:
        result["server"] = server_info

    # Backend — z ciasteczek sesyjnych ORAZ z nagłówków serwera (język/runtime).
    set_cookie = h.get("set-cookie", "").lower()
    server_blob = " ".join(server_info.values()).lower()
    backends = {name for needle, name in COOKIE_SIGNATURES.items() if needle in set_cookie}
    backends |= {name for needle, name in SERVER_BACKEND.items() if needle in server_blob}
    if backends:
        result["backend"] = sorted(backends)

    # Sygnatury HTML pogrupowane w kategorie.
    stack = {}
    for category, sigs in TECH_SIGNATURES.items():
        hits = sorted(name for name, markers in sigs.items() if any(m in body for m in markers))
        if hits:
            stack[category] = hits
    if stack:
        result["stack"] = stack

    # Frontend: wykryte frameworki albo "vanilla", gdy żadnego nie widać.
    fw = stack.get("framework", [])
    result["frontend"] = fw if fw else ["vanilla / brak wykrytego frameworka JS"]

    # API / GraphQL — pasywnie z HTML + aktywna sonda GraphQL.
    api_hints = []
    if "swagger" in body or "openapi" in body:
        api_hints.append("Swagger/OpenAPI")
    if "graphql" in body:
        api_hints.append("GraphQL (wzmianka w HTML)")
    gql_path = _detect_graphql(result["final_url"] if result["final_url"].startswith("http") else url)
    if gql_path:
        api_hints.append(f"GraphQL potwierdzony ({gql_path})")
    if api_hints:
        result["api"] = api_hints

    result["note"] = "Fingerprint pasywny + sonda GraphQL. Orientacyjnie, nie pełny Wappalyzer."
    return result


# Lista źródeł: (nazwa, jakich typów IOC dotyczy, funkcja wzbogacająca).
# Dodanie kolejnego źródła (np. VirusTotal) = jedna linijka tutaj + funkcja wyżej.
ENRICHERS = [
    ("dns", {"ip", "domain"}, enrich_dns),
    ("whois", {"ip", "domain"}, enrich_whois),
    ("tor", {"ip"}, enrich_tor),
    ("cdn", {"domain"}, enrich_cdn),
    ("crt", {"domain"}, enrich_crtsh),
    ("tech", {"domain", "url"}, enrich_tech),
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
            # Powiadamiamy przez kanał Postgresa — API to usłyszy i wypchnie do przeglądarki.
            # NOTIFY dochodzi dopiero po COMMIT (poniżej), więc kolejność jest OK.
            cur.execute("SELECT pg_notify('enrichments', %s)", (str(ioc_id),))
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
