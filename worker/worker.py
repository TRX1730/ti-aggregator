import os
import re
import time
import socket
import ipaddress
import dns.resolver

import psycopg
from psycopg.types.json import Json
import requests

DATABASE_URL = os.environ["DATABASE_URL"]
POLL_SECONDS = 5


def enrich_dns(ioc_type: str, value: str) -> dict:
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
    h = {}
    for k in ("handle", "ldhName", "name", "country", "startAddress", "endAddress", "type"):
        if data.get(k) is not None:
            h[k] = data[k]
    if data.get("status"):
        h["status"] = data["status"]
    return h


def enrich_whois(ioc_type: str, value: str) -> dict:
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
    return {"highlights": _rdap_highlights(data), "raw": data}


TOR_LIST_URL = "https://check.torproject.org/torbulkexitlist"
TOR_TTL = 3600
_tor_cache = {"ips": set(), "fetched_at": 0.0}


def _get_tor_exits() -> set:
    now = time.time()
    if not _tor_cache["ips"] or (now - _tor_cache["fetched_at"] > TOR_TTL):
        resp = requests.get(TOR_LIST_URL, timeout=15)
        resp.raise_for_status()
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


CF_URLS = ["https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"]
CF_TTL = 24 * 3600
_cf_cache = {"nets": [], "fetched_at": 0.0}

CDN_HOST_PATTERNS = {
    "akamai": ["akamai", "akamaitechnologies", "akamaiedge", "edgekey", "edgesuite"],
    "fastly": ["fastly"],
    "cloudfront": ["cloudfront"],
}

ORIGIN_PREFIXES = ["direct", "origin", "ftp", "cpanel", "webmail", "mail", "server", "vpn", "dev"]


def _get_cloudflare_nets() -> list:
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
    if any(_ip_in_nets(ip, cf_nets) for ip in ips):
        return "cloudflare"
    for ip in ips:
        host = _reverse_dns(ip)
        if host:
            for provider, needles in CDN_HOST_PATTERNS.items():
                if any(n in host for n in needles):
                    return provider
    return None


def enrich_cdn(ioc_type: str, value: str) -> dict:
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
            non_cdn = [ip for ip in _resolve(host) if _detect_provider([ip], cf_nets) is None]
            if non_cdn:
                candidates.append({"subdomain": host, "ips": non_cdn})
        result["origin_candidates"] = candidates
        result["origin_note"] = "Kandydaci na origin z heurystyki. NIEPEWNE — wymaga weryfikacji."

    return result


def enrich_crtsh(ioc_type: str, value: str) -> dict:
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
    return {"count": len(subs), "subdomains": subs[:200]}


TECH_SIGNATURES = {
    "cms": {
        "WordPress": ["wp-content", "wp-includes"],
        "Drupal": ["/sites/default/", "drupal-settings-json", "drupal.js"],
        "Joomla": ["/media/jui/", "joomla"],
        "Ghost": ["/ghost/", "ghost-"],
        "Wix": ["static.wixstatic.com", "wix.com"],
        "Squarespace": ["squarespace"],
        "Webflow": ["webflow"],
        "TYPO3": ["typo3temp", "typo3conf"],
        "Sitecore": ["/sitecore/", "sitecore"],
        "Adobe Experience Manager": ["/etc.clientlibs/", "/content/dam/", "cq-"],
        "Contentful": ["contentful"],
    },
    "commerce": {
        "Shopify": ["cdn.shopify.com", "myshopify.com"],
        "Magento / Adobe Commerce": ["magento", "mage-cache-storage", "/static/frontend/"],
        "WooCommerce": ["woocommerce"],
        "PrestaShop": ["prestashop"],
        "BigCommerce": ["bigcommerce"],
        "SAP Commerce (Hybris)": ["hybris", "/_ui/"],
    },
    "enterprise": {
        "Salesforce": ["force.com", "salesforce"],
        "ServiceNow": ["servicenow"],
        "SAP": ["sap.com", "/sap/"],
        "Oracle": ["oracle-adf", "/webcenter/"],
    },
    "hosting": {
        "AWS": ["s3.amazonaws.com", "cloudfront.net", "elasticbeanstalk", "awsstatic"],
        "Google Cloud": ["storage.googleapis.com", "appspot.com", "googleusercontent"],
        "Microsoft Azure": ["azurewebsites.net", "azureedge.net", "azure"],
        "Netlify": ["netlify"],
        "Vercel": ["vercel"],
        "Heroku": ["herokuapp.com"],
        "Fastly": ["fastly"],
    },
    "framework": {
        "React": ["data-reactroot", "__react", "react-dom", "reactcurrentdispatcher", "react.production"],
        "Vue.js": ["__vue__", "data-v-", "vue.js", "__vue_app__"],
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

COOKIE_SIGNATURES = {
    "phpsessid": "PHP",
    "laravel_session": "Laravel",
    "connect.sid": "Express / Node.js",
    "csrftoken": "Django",
    "jsessionid": "Java (JSP/Servlet)",
    "ci_session": "CodeIgniter",
    "asp.net": "ASP.NET",
}

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
    base = str(resp.url)
    html = resp.text[:400000]
    js_text = ""
    for src in re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', resp.text, re.I)[:3]:
        if src.startswith("//"):
            js_url = "https:" + src
        elif src.startswith("http"):
            js_url = src
        else:
            js_url = base.rstrip("/") + "/" + src.lstrip("/")
        try:
            jr = requests.get(js_url, timeout=10, headers={"User-Agent": "ti-platform"})
            if jr.status_code == 200:
                js_text += jr.text[:300000]
        except Exception:
            pass
    body = (html + " " + js_text).lower()
    result = {"status_code": resp.status_code, "final_url": base}

    server_info = {}
    for hk in ("server", "x-powered-by", "x-generator", "x-aspnet-version", "via"):
        if hk in h:
            server_info[hk] = h[hk]
    if server_info:
        result["server"] = server_info

    server_raw = h.get("server", "").lower()
    for needle, name in (("nginx", "nginx"), ("openresty", "OpenResty"), ("apache", "Apache"),
                         ("microsoft-iis", "IIS"), ("litespeed", "LiteSpeed"), ("caddy", "Caddy"),
                         ("envoy", "Envoy"), ("cloudflare", "Cloudflare")):
        if needle in server_raw:
            result["web_server"] = name
            break
    proxies = []
    if "via" in h:
        proxies.append("Via: " + h["via"][:80])
    if "x-varnish" in h:
        proxies.append("Varnish")
    if "cf-ray" in h:
        proxies.append("Cloudflare")
    if "x-cache" in h or "x-served-by" in h:
        proxies.append("cache/CDN")
    if proxies:
        result["proxy"] = proxies

    set_cookie = h.get("set-cookie", "").lower()
    server_blob = " ".join(server_info.values()).lower()
    backends = {name for needle, name in COOKIE_SIGNATURES.items() if needle in set_cookie}
    backends |= {name for needle, name in SERVER_BACKEND.items() if needle in server_blob}
    if backends:
        result["backend"] = sorted(backends)

    stack = {}
    for category, sigs in TECH_SIGNATURES.items():
        hits = sorted(name for name, markers in sigs.items() if any(m in body for m in markers))
        if hits:
            stack[category] = hits
    if stack:
        result["stack"] = stack

    fw = stack.get("framework", [])
    result["frontend"] = fw if fw else ["vanilla / brak wykrytego frameworka JS"]

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


def enrich_dnsrecords(ioc_type: str, value: str) -> dict:
    if ioc_type != "domain":
        return {"error": "dns_records: dotyczy tylko domen"}
    result = {}
    for rtype in ("MX", "NS", "TXT"):
        try:
            ans = dns.resolver.resolve(value, rtype, lifetime=8)
            result[rtype] = [str(r).strip().strip('"') for r in ans]
        except Exception:
            pass
    spf = [t for t in result.get("TXT", []) if "v=spf1" in t.lower()]
    if spf:
        result["SPF"] = spf
    try:
        dmarc = dns.resolver.resolve("_dmarc." + value, "TXT", lifetime=8)
        result["DMARC"] = [str(r).strip().strip('"') for r in dmarc]
    except Exception:
        pass
    if not result:
        result["note"] = "brak rekordów albo nie rozwiązano"
    return result


def enrich_wayback(ioc_type: str, value: str) -> dict:
    if ioc_type != "domain":
        return {"error": "wayback: dotyczy tylko domen"}
    url = (f"http://web.archive.org/cdx/search/cdx?url={value}/*"
           f"&output=json&fl=original&collapse=urlkey&limit=300")
    try:
        resp = requests.get(url, timeout=20, headers={"User-Agent": "ti-platform"})
        resp.raise_for_status()
        rows = resp.json()
    except Exception as e:
        return {"error": str(e)}
    urls = [r[0] for r in rows[1:]] if isinstance(rows, list) and len(rows) > 1 else []
    return {"count": len(urls), "sample": urls[:50]}


def enrich_geoip(ioc_type: str, value: str) -> dict:
    if ioc_type != "ip":
        return {"error": "geoip: dotyczy tylko IP"}
    try:
        r = requests.get(f"http://ip-api.com/json/{value}?fields=status,country,city,isp,org,as", timeout=10)
        data = r.json()
    except Exception as e:
        return {"error": str(e)}
    if data.get("status") != "success":
        return {"error": "geoip: brak danych"}
    result = {"country": data.get("country"), "city": data.get("city"),
              "isp": data.get("isp"), "org": data.get("org"), "as": data.get("as")}
    m = re.match(r"AS(\d+)", data.get("as") or "")
    if m:
        try:
            rr = requests.get(
                f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{m.group(1)}",
                timeout=15)
            prefixes = [p["prefix"] for p in rr.json().get("data", {}).get("prefixes", [])]
            result["asn_prefixes_count"] = len(prefixes)
            result["asn_prefixes_sample"] = prefixes[:20]
        except Exception:
            pass
    return result


BLOCKLIST_TTL = 6 * 3600
_bl_cache = {}


def _cached_set(key: str, url: str, parse) -> set:
    now = time.time()
    entry = _bl_cache.get(key)
    if entry and now - entry[1] <= BLOCKLIST_TTL:
        return entry[0]
    resp = requests.get(url, timeout=20, headers={"User-Agent": "ti-platform"})
    resp.raise_for_status()
    s = set()
    for line in resp.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        v = parse(line)
        if v:
            s.add(v)
    _bl_cache[key] = (s, now)
    print(f"[worker] blocklist {key}: {len(s)} wpisów", flush=True)
    return s


def _cert_domains() -> set:
    return _cached_set("cert", "https://hole.cert.pl/domains/v2/domains.txt", lambda l: l.lower())


def _urlhaus_domains() -> set:
    def p(l):
        parts = l.split()
        d = parts[-1].lower() if parts else ""
        return d if d and d != "localhost" else None
    return _cached_set("urlhaus", "https://urlhaus.abuse.ch/downloads/hostfile/", p)


def _feodo_ips() -> set:
    return _cached_set("feodo", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", lambda l: l)


def enrich_blocklist(ioc_type: str, value: str) -> dict:
    hits = []
    try:
        if ioc_type == "domain":
            v = value.lower()
            if v in _cert_domains():
                hits.append("CERT Polska (Lista ostrzeżeń)")
            if v in _urlhaus_domains():
                hits.append("abuse.ch URLhaus")
        elif ioc_type == "ip":
            if value in _feodo_ips():
                hits.append("abuse.ch Feodo Tracker (C2)")
        else:
            return {"error": "blocklist: dotyczy ip/domain"}
    except Exception as e:
        return {"error": str(e)}
    return {"on_blocklist": len(hits) > 0, "sources": hits}


VT_API_KEY = os.environ.get("VT_API_KEY", "")
VT_MIN_INTERVAL = 16
_vt_last = 0.0


def enrich_virustotal(ioc_type: str, value: str) -> dict:
    global _vt_last
    if not VT_API_KEY:
        return {"error": "brak VT_API_KEY (ustaw w .env)"}
    if ioc_type == "domain":
        url = f"https://www.virustotal.com/api/v3/domains/{value}"
    elif ioc_type == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{value}"
    elif ioc_type == "hash":
        url = f"https://www.virustotal.com/api/v3/files/{value}"
    else:
        return {"error": "virustotal: dotyczy ip/domain/hash"}

    wait = VT_MIN_INTERVAL - (time.time() - _vt_last)
    if wait > 0:
        time.sleep(wait)
    _vt_last = time.time()

    try:
        r = requests.get(url, headers={"x-apikey": VT_API_KEY}, timeout=20)
    except Exception as e:
        return {"error": str(e)}
    if r.status_code == 404:
        return {"error": "brak danych w VT"}
    if r.status_code == 429:
        return {"error": "limit VT (429)"}
    if r.status_code != 200:
        return {"error": f"VT HTTP {r.status_code}"}

    attrs = r.json().get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {}) or {}
    result = {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "total_engines": sum(stats.values()) if stats else 0,
        "reputation": attrs.get("reputation"),
    }
    if ioc_type == "hash":
        result["type_description"] = attrs.get("type_description")
        names = attrs.get("names") or []
        if names:
            result["names"] = names[:5]

    results = attrs.get("last_analysis_results", {}) or {}
    detections = [
        {"engine": eng, "result": res.get("result")}
        for eng, res in results.items()
        if res.get("category") in ("malicious", "suspicious")
    ]
    if detections:
        result["detections"] = detections[:40]
    return result


def enrich_shodan(ioc_type: str, value: str) -> dict:
    if ioc_type != "ip":
        return {"error": "shodan: dotyczy tylko IP"}
    try:
        r = requests.get(f"https://internetdb.shodan.io/{value}", timeout=12,
                         headers={"User-Agent": "ti-platform"})
    except Exception as e:
        return {"error": str(e)}
    if r.status_code == 404:
        return {"ports": [], "vulns": [], "note": "brak danych w Shodan InternetDB"}
    if r.status_code != 200:
        return {"error": f"shodan HTTP {r.status_code}"}
    d = r.json()
    return {
        "ports": d.get("ports", []),
        "hostnames": d.get("hostnames", []),
        "tags": d.get("tags", []),
        "vulns": d.get("vulns", []),
        "cpes": (d.get("cpes") or [])[:10],
    }


_tf_cache = {"map": {}, "fetched_at": 0.0}


def _threatfox_map() -> dict:
    now = time.time()
    if _tf_cache["map"] and now - _tf_cache["fetched_at"] <= BLOCKLIST_TTL:
        return _tf_cache["map"]
    resp = requests.get("https://threatfox.abuse.ch/export/json/recent/", timeout=25,
                        headers={"User-Agent": "ti-platform"})
    resp.raise_for_status()
    data = resp.json()
    m = {}
    for entries in data.values():
        for e in entries:
            v = str(e.get("ioc_value", "")).strip().lower()
            fam = e.get("malware_printable") or e.get("malware") or "?"
            if v:
                m[v] = fam
                if ":" in v:
                    m[v.split(":")[0]] = fam
    _tf_cache["map"] = m
    _tf_cache["fetched_at"] = now
    print(f"[worker] ThreatFox: {len(m)} IOC", flush=True)
    return m


def enrich_threatfox(ioc_type: str, value: str) -> dict:
    if ioc_type not in ("ip", "domain", "hash"):
        return {"error": "threatfox: dotyczy ip/domain/hash"}
    try:
        m = _threatfox_map()
    except Exception as e:
        return {"error": str(e)}
    fam = m.get(value.lower())
    return {"on_threatfox": fam is not None, "malware": fam}


ENRICHERS = [
    ("dns", {"ip", "domain"}, enrich_dns),
    ("whois", {"ip", "domain"}, enrich_whois),
    ("tor", {"ip"}, enrich_tor),
    ("cdn", {"domain"}, enrich_cdn),
    ("crt", {"domain"}, enrich_crtsh),
    ("tech", {"domain", "url"}, enrich_tech),
    ("dns_records", {"domain"}, enrich_dnsrecords),
    ("wayback", {"domain"}, enrich_wayback),
    ("geoip", {"ip"}, enrich_geoip),
    ("blocklist", {"ip", "domain"}, enrich_blocklist),
    ("shodan", {"ip"}, enrich_shodan),
    ("threatfox", {"ip", "domain", "hash"}, enrich_threatfox),
    ("virustotal", {"ip", "domain", "hash"}, enrich_virustotal),
]


def process_source(conn, source: str, types: set, fn) -> int:
    with conn.cursor() as cur:
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
            cur.execute("SELECT pg_notify('enrichments', %s)", (str(ioc_id),))
            print(f"[worker] {source}: IOC {ioc_id} ({value})", flush=True)
            time.sleep(0.5)

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
