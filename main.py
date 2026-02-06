# main.py
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, List
import httpx
from urllib.parse import urlparse
import socket
import ipaddress
import re

APP_NAME = "Security Headers Checker API"
APP_DESC = (
    "Checks common web security headers for a given URL and returns a JSON report."
)

app = FastAPI(title=APP_NAME, description=APP_DESC, version="1.0.0")

# Allow CORS for all origins; tighten if needed
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- Models ----------
class HeaderCheck(BaseModel):
    present: bool
    value: str | None
    verdict: str
    recommendation: str | None = None

class CheckResult(BaseModel):
    url_final: str
    status_code: int | None
    https_enforced: bool
    headers: Dict[str, HeaderCheck]
    issues: List[str]
    score_out_of_100: int

# ---------- Utilities ----------
PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),     # loopback
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
    ipaddress.ip_network("::1/128"),         # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),        # unique local
    ipaddress.ip_network("fe80::/10"),       # IPv6 link-local
    ipaddress.ip_network("100.64.0.0/10"),   # CGNAT
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),    # TEST-NET-1
    ipaddress.ip_network("198.18.0.0/15"),   # benchmarking
    ipaddress.ip_network("198.51.100.0/24"), # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),     # multicast
]

LOCALHOST_NAMES = {"localhost", "ip6-localhost", "local"}

def is_ip_disallowed(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    if (
        ip_obj.is_unspecified
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_reserved
        or ip_obj.is_multicast
    ):
        return True
    for net in PRIVATE_NETS:
        if ip_obj in net:
            return True
    return False

def resolve_and_block_internal(hostname: str):
    # Quick hostname denylist
    if hostname.lower() in LOCALHOST_NAMES or hostname.endswith(".local"):
        raise HTTPException(status_code=400, detail="Blocked hostname")
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        raise HTTPException(status_code=400, detail="Cannot resolve hostname")
    ips = set()
    for info in infos:
        addr = info[4][0]
        ips.add(addr)
    for ip in ips:
        if is_ip_disallowed(ip):
            raise HTTPException(status_code=400, detail="Blocked IP/network")
    return ips

def normalize_url(u: str) -> str:
    u = u.strip()
    if not re.match(r"^https?://", u, flags=re.IGNORECASE):
        u = "https://" + u
    parsed = urlparse(u)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise HTTPException(status_code=400, detail="Invalid URL")
    return u

# ---------- Header checks ----------
def check_hsts(value: str | None, is_https: bool) -> HeaderCheck:
    if not value:
        verdict = "missing"
        rec = "Add Strict-Transport-Security with max-age>=31536000; includeSubDomains; preload"
        return HeaderCheck(present=False, value=None, verdict=verdict, recommendation=rec)

    vlow = value.lower()
    max_age = 0
    m = re.search(r"max-age\s*=\s*(\d+)", vlow)
    if m:
        max_age = int(m.group(1))
    include_sub = "includesubdomains" in vlow
    preload = "preload" in vlow

    ok_age = max_age >= 31536000
    if is_https and ok_age and include_sub:
        verdict = "good (preload recommended)" if not preload else "excellent"
        rec = None if preload else "Consider adding 'preload' and submitting to HSTS preload list"
    else:
        verdict = "weak"
        rec = "Use HSTS with max-age>=31536000; includeSubDomains; preload (HTTPS only)"
    return HeaderCheck(present=True, value=value, verdict=verdict, recommendation=rec)

def check_csp(value: str | None) -> HeaderCheck:
    if not value:
        return HeaderCheck(
            present=False,
            value=None,
            verdict="missing",
            recommendation="Add a Content-Security-Policy. Start with \"default-src 'self'\"; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
        )
    v = value.lower()
    issues = []
    if "'unsafe-inline'" in v:
        issues.append("Avoid 'unsafe-inline' (use nonces or hashes)")
    if "'unsafe-eval'" in v:
        issues.append("Avoid 'unsafe-eval'")
    if "object-src" not in v or "object-src 'none'" not in v:
        issues.append("Set 'object-src 'none''")
    if "base-uri" not in v:
        issues.append("Set 'base-uri 'self''")
    if "frame-ancestors" not in v:
        issues.append("Set 'frame-ancestors' (or use X-Frame-Options)")
    verdict = "good" if not issues else "present-with-issues"
    rec = "; ".join(issues) if issues else None
    return HeaderCheck(present=True, value=value, verdict=verdict, recommendation=rec)

def check_simple_equal(value: str | None, expected_values: List[str], name: str, rec_text: str) -> HeaderCheck:
    if not value:
        return HeaderCheck(present=False, value=None, verdict="missing", recommendation=rec_text)
    if value.strip().lower() in [v.lower() for v in expected_values]:
        return HeaderCheck(present=True, value=value, verdict="good", recommendation=None)
    return HeaderCheck(present=True, value=value, verdict="unusual", recommendation=f"Recommended: {', '.join(expected_values)}")

def check_referrer_policy(value: str | None) -> HeaderCheck:
    good = {"no-referrer", "same-origin", "strict-origin-when-cross-origin"}
    if not value:
        return HeaderCheck(present=False, value=None, verdict="missing", recommendation="Use 'strict-origin-when-cross-origin' or 'no-referrer'")
    v = value.strip().lower()
    if v in good:
        return HeaderCheck(present=True, value=value, verdict="good")
    return HeaderCheck(present=True, value=value, verdict="ok", recommendation="Prefer 'strict-origin-when-cross-origin'")

def score(headers: Dict[str, HeaderCheck], https_enforced: bool) -> int:
    total = 0
    parts = 0

    def add(h: str, weight: int = 10):
        nonlocal total, parts
        parts += weight
        hc = headers.get(h)
        if not hc or not hc.present:
            return
        if hc.verdict in ("good", "excellent"):
            total += weight
        elif hc.verdict in ("present-with-issues", "weak", "ok", "unusual"):
            total += int(weight * 0.5)

    add("strict-transport-security", 20)
    add("content-security-policy", 20)
    add("x-content-type-options", 10)
    add("x-frame-options", 10)
    add("referrer-policy", 10)
    add("permissions-policy", 10)
    add("cross-origin-opener-policy", 5)
    add("cross-origin-embedder-policy", 5)
    add("cross-origin-resource-policy", 5)

    if https_enforced:
        total += 5
        parts += 5

    return int((total / parts) * 100) if parts else 0

# ---------- Routes ----------
@app.get("/")
def root():
    return {
        "message": "Security Headers Checker API",
        "usage": "/check?url=https://example.com",
        "docs": "/docs",
        "health": "/healthz"
    }

@app.get("/healthz")
def healthz():
    return {"status": "ok"}

@app.get("/check", response_model=CheckResult)
async def check(url: str = Query(..., description="Target URL (http/https). E.g., https://example.com")):
    # Normalize and guard
    target = normalize_url(url)
    parsed = urlparse(target)
    resolve_and_block_internal(parsed.hostname)

    timeout = httpx.Timeout(10.0, connect=5.0)
    headers_out: Dict[str, HeaderCheck] = {}
    issues: List[str] = []

    async with httpx.AsyncClient(follow_redirects=True, timeout=timeout) as client:
        try:
            # Some servers misbehave on HEAD; use GET but don't stream full content
            resp = await client.get(target, headers={"User-Agent": f"{APP_NAME}/1.0"}, max_redirects=5)
            final_url = str(resp.url)
            status_code = resp.status_code
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
        except httpx.TooManyRedirects:
            raise HTTPException(status_code=400, detail="Too many redirects")
        except httpx.HTTPError as e:
            raise HTTPException(status_code=502, detail=f"HTTP error: {e}")

    is_https = urlparse(final_url).scheme == "https"
    https_enforced = is_https

    # Build checks
    headers_out["strict-transport-security"] = check_hsts(resp_headers.get("strict-transport-security"), is_https)
    headers_out["content-security-policy"] = check_csp(resp_headers.get("content-security-policy"))
    headers_out["x-content-type-options"] = check_simple_equal(
        resp_headers.get("x-content-type-options"), ["nosniff"], "X-Content-Type-Options", "Set 'X-Content-Type-Options: nosniff'"
    )
    # X-Frame-Options is legacy but still useful if CSP frame-ancestors absent
    headers_out["x-frame-options"] = check_simple_equal(
        resp_headers.get("x-frame-options"), ["deny", "sameorigin"], "X-Frame-Options", "Use 'DENY' or 'SAMEORIGIN' or CSP 'frame-ancestors'"
    )
    headers_out["referrer-policy"] = check_referrer_policy(resp_headers.get("referrer-policy"))
    headers_out["permissions-policy"] = HeaderCheck(
        present=resp_headers.get("permissions-policy") is not None,
        value=resp_headers.get("permissions-policy"),
        verdict="good" if resp_headers.get("permissions-policy") else "missing",
        recommendation=None if resp_headers.get("permissions-policy") else "Set a restrictive 'Permissions-Policy' (e.g., geolocation=())"
    )
    headers_out["cross-origin-opener-policy"] = check_simple_equal(
        resp_headers.get("cross-origin-opener-policy"), ["same-origin", "same-origin-allow-popups"], "COOP",
        "Set 'Cross-Origin-Opener-Policy: same-origin'"
    )
    headers_out["cross-origin-embedder-policy"] = check_simple_equal(
        resp_headers.get("cross-origin-embedder-policy"), ["require-corp"], "COEP",
        "Set 'Cross-Origin-Embedder-Policy: require-corp'"
    )
    headers_out["cross-origin-resource-policy"] = check_simple_equal(
        resp_headers.get("cross-origin-resource-policy"), ["same-origin", "same-site", "cross-origin"], "CORP",
        "Set 'Cross-Origin-Resource-Policy: same-origin' (or 'same-site')"
    )

    # Legacy awareness (not scored)
    if "x-xss-protection" not in resp_headers:
        issues.append("X-XSS-Protection is obsolete; absence is fine on modern browsers")
    if "expect-ct" in resp_headers:
        issues.append("Expect-CT is deprecated; safe to remove")

    # HTTPS note
    if not is_https:
        issues.append("Final URL is not HTTPS; enable HTTPS and HSTS")

    score_val = score(headers_out, https_enforced)

    return CheckResult(
        url_final=final_url,
        status_code=status_code,
        https_enforced=https_enforced,
        headers=headers_out,
        issues=issues,
        score_out_of_100=score_val
    )
