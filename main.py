# main.py
import logging
import traceback
import re
import socket
import ipaddress
from typing import Dict, List, Optional

import httpx
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from urllib.parse import urlparse

# ------------------ App Metadata ------------------
APP_NAME = "Security Headers Checker API"
APP_DESC = "Checks common web security headers for a given URL and returns a JSON report."

# ------------------ FastAPI App -------------------
app = FastAPI(title=APP_NAME, description=APP_DESC, version="1.1.0")

# CORS: open by default; tighten as needed
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("security-headers-api")

# ------------------ Models ------------------------
class HeaderCheck(BaseModel):
    present: bool
    value: Optional[str] = None
    verdict: str
    recommendation: Optional[str] = None

class CheckResult(BaseModel):
    url_final: str
    status_code: Optional[int] = None
    https_enforced: bool
    headers: Dict[str, HeaderCheck]
    issues: List[str]
    score_out_of_100: int

# ------------------ SSRF Guards -------------------
PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),      # loopback
    ipaddress.ip_network("169.254.0.0/16"),   # link-local
    ipaddress.ip_network("::1/128"),          # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),         # IPv6 unique local
    ipaddress.ip_network("fe80::/10"),        # IPv6 link-local
    ipaddress.ip_network("100.64.0.0/10"),    # CGNAT
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),     # TEST-NET-1
    ipaddress.ip_network("198.18.0.0/15"),    # benchmarking
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),   # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),      # multicast
]

LOCALHOST_NAMES = {"localhost", "ip6-localhost", "local"}

def is_ip_disallowed(ip_str: str) -> bool:
    """Return True if the IP is in a private/reserved/multicast/loopback/etc range."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        # Unparseable IP => disallow to be safe
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
    """Resolve hostname and block if any address is internal/disallowed."""
    if not hostname:
        raise HTTPException(status_code=400, detail="Invalid URL hostname")

    # Quick hostname denylist
    if hostname.lower() in LOCALHOST_NAMES or hostname.endswith(".local"):
        raise HTTPException(status_code=400, detail="Blocked hostname")

    # IDNA (punycode) normalize for resolution
    try:
        host_idna = hostname.encode("idna").decode("ascii")
    except Exception:
        host_idna = hostname

    try:
        infos = socket.getaddrinfo(host_idna, None)
    except socket.gaierror:
        raise HTTPException(status_code=400, detail="Cannot resolve hostname")

    ips = set()
    for info in infos:
        addr = info[4][0]
        ips.add(addr)

    for ip in ips:
        if is_ip_disallowed(ip):
            raise HTTPException(status_code=400, detail=f"Blocked IP/network: {ip}")

    return ips

def normalize_url(u: str) -> str:
    """Ensure URL has scheme and is http/https, reject creds in URL."""
    u = (u or "").strip()
    if not re.match(r"^https?://", u, flags=re.IGNORECASE):
        u = "https://" + u
    parsed = urlparse(u)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise HTTPException(status_code=400, detail="Invalid URL")
    if parsed.username or parsed.password:
        raise HTTPException(status_code=400, detail="Userinfo in URL is not allowed")
    return u

# ------------------ Header Checks -----------------
def check_hsts(value: Optional[str], is_https: bool) -> HeaderCheck:
    if not value:
        return HeaderCheck(
            present=False,
            verdict="missing",
            recommendation="Add Strict-Transport-Security with max-age>=31536000; includeSubDomains; preload",
        )

    vlow = value.lower()
    max_age = 0
    m = re.search(r"max-age\s*=\s*(\d+)", vlow)
    if m:
        try:
            max_age = int(m.group(1))
        except ValueError:
            max_age = 0

    include_sub = "includesubdomains" in vlow
    preload = "preload" in vlow
    ok_age = max_age >= 31536000

    if is_https and ok_age and include_sub:
        verdict = "excellent" if preload else "good (preload recommended)"
        rec = None if preload else "Consider adding 'preload' and submitting to HSTS preload list"
    else:
        verdict = "weak"
        rec = "Use HSTS with max-age>=31536000; includeSubDomains; preload (HTTPS only)"
    return HeaderCheck(present=True, value=value, verdict=verdict, recommendation=rec)

def check_csp(value: Optional[str]) -> HeaderCheck:
    if not value:
        return HeaderCheck(
            present=False,
            verdict="missing",
            recommendation='Add a Content-Security-Policy. Start with "default-src \'self\'"; object-src \'none\'; base-uri \'self\'; frame-ancestors \'none\'',
        )
    v = value.lower()
    issues: List[str] = []
    if "'unsafe-inline'" in v:
        issues.append("Avoid 'unsafe-inline' (use nonces or hashes)")
    if "'unsafe-eval'" in v:
        issues.append("Avoid 'unsafe-eval'")
    if "object-src 'none'" not in v:
        issues.append("Set 'object-src 'none''")
    if "base-uri 'self'" not in v:
        issues.append("Set 'base-uri 'self''")
    if "frame-ancestors 'none'" not in v:
        issues.append("Set 'frame-ancestors' (or use X-Frame-Options)")
    verdict = "good" if not issues else "present-with-issues"
    rec = "; ".join(issues) if issues else None
    return HeaderCheck(present=True, value=value, verdict=verdict, recommendation=rec)

def check_simple_equal(value: Optional[str], expected_values: List[str], _name: str, rec_text: str) -> HeaderCheck:
    if not value:
        return HeaderCheck(present=False, verdict="missing", recommendation=rec_text)
    if value.strip().lower() in [v.lower() for v in expected_values]:
        return HeaderCheck(present=True, value=value, verdict="good")
    return HeaderCheck(
        present=True,
        value=value,
        verdict="unusual",
        recommendation=f"Recommended: {', '.join(expected_values)}",
    )

def check_referrer_policy(value: Optional[str]) -> HeaderCheck:
    good = {"no-referrer", "same-origin", "strict-origin-when-cross-origin"}
    if not value:
        return HeaderCheck(
            present=False,
            verdict="missing",
            recommendation="Use 'strict-origin-when-cross-origin' or 'no-referrer'",
        )
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

# ------------------ Routes ------------------------
@app.get("/")
def root():
    return {
        "message": "Security Headers Checker API",
        "usage": "/check?url=https://example.com",
        "docs": "/docs",
        "health": "/healthz",
    }

@app.get("/healthz")
def healthz():
    return {"status": "ok"}

@app.get("/check", response_model=CheckResult)
async def check(url: str = Query(..., description="Target URL (http/https). E.g., https://example.com")):
    try:
        # Normalize + SSRF guard
        target = normalize_url(url)
        parsed = urlparse(target)
        resolve_and_block_internal(parsed.hostname)

        timeout = httpx.Timeout(15.0, connect=8.0)

        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=timeout,
            http2=False,  # keep simple; some targets are picky with H2 from cloud egress IPs
            headers={"User-Agent": f"{APP_NAME}/1.0 (+https://security-headers-api.onrender.com)"},
        ) as client:
            resp = None

            # Try HEAD (polite, fast), fall back to GET if HEAD is not useful
            try:
                head = await client.head(target)
                if head.status_code >= 400 or not head.headers:
                    raise httpx.HTTPStatusError("HEAD not useful", request=head.request, response=head)
                resp = head
            except Exception as e_head:
                logger.info(f"HEAD failed for {target}: {e_head}; falling back to GET")
                try:
                    resp = await client.get(target)
                except httpx.HTTPError as e:
                    # network errors, DNS, TLS, timeouts → 502
                    raise HTTPException(status_code=502, detail=f"Upstream HTTP error: {str(e)}")

            final_url = str(resp.url)
            status_code = resp.status_code
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}

        is_https = urlparse(final_url).scheme == "https"
        https_enforced = is_https

        # Build checks
        headers_out: Dict[str, HeaderCheck] = {}
        issues: List[str] = []

        headers_out["strict-transport-security"] = check_hsts(resp_headers.get("strict-transport-security"), is_https)
        headers_out["content-security-policy"] = check_csp(resp_headers.get("content-security-policy"))
        headers_out["x-content-type-options"] = check_simple_equal(
            resp_headers.get("x-content-type-options"), ["nosniff"], "X-Content-Type-Options", "Set 'X-Content-Type-Options: nosniff'"
        )
        headers_out["x-frame-options"] = check_simple_equal(
            resp_headers.get("x-frame-options"), ["deny", "sameorigin"], "X-Frame-Options", "Use 'DENY' or 'SAMEORIGIN' or CSP 'frame-ancestors'"
        )
        headers_out["referrer-policy"] = check_referrer_policy(resp_headers.get("referrer-policy"))
        headers_out["permissions-policy"] = HeaderCheck(
            present=resp_headers.get("permissions-policy") is not None,
            value=resp_headers.get("permissions-policy"),
            verdict="good" if resp_headers.get("permissions-policy") else "missing",
            recommendation=None if resp_headers.get("permissions-policy") else "Set a restrictive 'Permissions-Policy' (e.g., geolocation=())",
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

        if not is_https:
            issues.append("Final URL is not HTTPS; enable HTTPS and HSTS")

        score_val = score(headers_out, https_enforced)

        result = CheckResult(
            url_final=final_url,
            status_code=status_code,
            https_enforced=https_enforced,
            headers=headers_out,
            issues=issues,
            score_out_of_100=score_val,
        )
        # Pretty JSON for browsers
        return JSONResponse(content=result.model_dump(), status_code=200, media_type="application/json")

    except HTTPException as hx:
        logger.warning(f"HTTPException: {hx.detail}")
        return JSONResponse(content={"detail": hx.detail}, status_code=hx.status_code)
    except Exception as e:
        logger.error("Unhandled exception in /check:\n" + traceback.format_exc())
        return JSONResponse(
            content={"detail": "Internal error while checking the target", "error": str(e)},
            status_code=500,
        )
