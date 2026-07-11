import re
import socket
import requests
import dns.resolver
import dns.query
import dns.zone

UA = {"User-Agent": "ti-platform-recon"}

SENSITIVE_FILES = {
    "/.env": ("critical", lambda t: ("=" in t and "\n" in t and "<html" not in t.lower()
                                     and any(k in t for k in ("APP_", "DB_", "SECRET", "KEY", "PASSWORD")))),
    "/.git/config": ("high", lambda t: "[core]" in t.lower()),
    "/.aws/credentials": ("critical", lambda t: "aws_access_key_id" in t.lower()),
}

ADMIN_PATHS = ["/admin", "/wp-admin/", "/phpmyadmin/", "/actuator", "/console", "/_debug", "/swagger-ui/"]
DIR_PATHS = ["/uploads/", "/images/", "/backup/", "/files/", "/static/"]
SEC_HEADERS = ["strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options"]
BACKUP_FILES = ["/index.php.bak", "/config.old", "/.DS_Store", "/web.config.bak", "/database.sql", "/backup.zip"]
SWAGGER_PATHS = ["/openapi.json", "/swagger.json", "/api-docs"]

TAKEOVER_FINGERPRINTS = [
    "there isn't a github pages site here",
    "nosuchbucket", "the specified bucket does not exist",
    "no such app", "fastly error: unknown domain",
    "do not have an app configured at that hostname",
    "project not found",
]

INTERNAL_IP_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b")

SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Slack token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
]
SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)


def _get(url):
    try:
        return requests.get(url, timeout=8, allow_redirects=True, headers=UA)
    except Exception:
        return None


def dns_zone_transfer(domain: str) -> list:
    findings = []
    try:
        ns_records = dns.resolver.resolve(domain, "NS", lifetime=8)
    except Exception:
        return findings
    for ns in ns_records:
        nsname = str(ns).rstrip(".")
        try:
            ns_ip = socket.gethostbyname(nsname)
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, lifetime=8))
            if zone is not None:
                findings.append({"severity": "high", "title": "DNS zone transfer (AXFR) dozwolony",
                                 "detail": f"NS {nsname} zwrócił całą strefę"})
                break
        except Exception:
            continue
    return findings


def run_checks(host: str) -> list:
    findings = []
    base = f"https://{host}"

    root = _get(base + "/")
    if root is None:
        return findings

    baseline = _get(base + "/zzz-nieistnieje-recon404")
    soft404 = baseline is not None and baseline.status_code == 200

    present = {k.lower() for k in root.headers}
    missing = [h for h in SEC_HEADERS if h not in present]
    if missing:
        findings.append({"severity": "low", "title": "Brakujące nagłówki bezpieczeństwa",
                         "detail": "brak: " + ", ".join(missing)})

    server = root.headers.get("Server", "")
    if server and any(c.isdigit() for c in server):
        findings.append({"severity": "low", "title": "Nagłówek Server ujawnia wersję", "detail": server})

    hdr_blob = " ".join(f"{k}: {v}" for k, v in root.headers.items())
    m = INTERNAL_IP_RE.search(hdr_blob)
    if m:
        findings.append({"severity": "medium", "title": "Wewnętrzne IP w nagłówkach", "detail": m.group(0)})

    bm = INTERNAL_IP_RE.search(root.text[:50000])
    if bm and (m is None or bm.group(0) != m.group(0)):
        findings.append({"severity": "medium", "title": "Wewnętrzne IP w treści odpowiedzi", "detail": bm.group(0)})

    low_body = root.text[:20000].lower()
    for fp in TAKEOVER_FINGERPRINTS:
        if fp in low_body:
            findings.append({"severity": "high", "title": "Możliwe subdomain takeover",
                             "detail": f"fingerprint: '{fp}'"})
            break

    for path, (sev, check) in SENSITIVE_FILES.items():
        r = _get(base + path)
        if r is not None and r.status_code == 200 and not soft404 and check(r.text[:5000]):
            findings.append({"severity": sev, "title": f"Odsłonięty plik {path}",
                             "detail": f"HTTP 200, {len(r.content)} B"})

    for path in BACKUP_FILES:
        r = _get(base + path)
        if r is not None and r.status_code == 200 and not soft404 and len(r.content) > 0 \
                and "<html" not in r.text[:500].lower():
            findings.append({"severity": "medium", "title": f"Odsłonięty plik backup {path}",
                             "detail": f"HTTP 200, {len(r.content)} B"})

    for path in ADMIN_PATHS:
        r = _get(base + path)
        if r is None:
            continue
        if r.status_code == 200 and not soft404:
            findings.append({"severity": "high", "title": f"Odsłonięty panel/endpoint {path}", "detail": "HTTP 200"})
        elif r.status_code in (401, 403):
            findings.append({"severity": "low", "title": f"Panel obecny (chroniony) {path}", "detail": f"HTTP {r.status_code}"})

    for path in SWAGGER_PATHS:
        r = _get(base + path)
        if r is not None and r.status_code == 200 and not soft404 \
                and ("openapi" in r.text[:2000].lower() or "swagger" in r.text[:2000].lower()):
            findings.append({"severity": "low", "title": f"Odsłonięta dokumentacja API {path}", "detail": "Swagger/OpenAPI"})

    for path in DIR_PATHS:
        r = _get(base + path)
        if r is not None and r.status_code == 200 and "index of /" in r.text[:2000].lower():
            findings.append({"severity": "medium", "title": f"Directory listing {path}", "detail": "'Index of' w odpowiedzi"})

    rb = _get(base + "/robots.txt")
    if rb is not None and rb.status_code == 200 and "user-agent" in rb.text[:2000].lower():
        disallows = [ln.split(":", 1)[1].strip() for ln in rb.text.splitlines()
                     if ln.lower().startswith("disallow:") and ln.split(":", 1)[1].strip()]
        if disallows:
            findings.append({"severity": "low", "title": "robots.txt ujawnia ścieżki",
                             "detail": ", ".join(disallows[:15])})

    for src in SCRIPT_SRC_RE.findall(root.text)[:2]:
        if src.startswith("//"):
            js_url = "https:" + src
        elif src.startswith("http"):
            js_url = src
        else:
            js_url = base + "/" + src.lstrip("/")
        rj = _get(js_url)
        if rj is None or rj.status_code != 200:
            continue
        for name, pat in SECRET_PATTERNS:
            if pat.search(rj.text[:200000]):
                findings.append({"severity": "medium", "title": f"Możliwy sekret w JS ({name})", "detail": js_url[:120]})
                break

    return findings
