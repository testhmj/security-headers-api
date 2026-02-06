# main.py
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, Any, List
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
    if ip_obj.is_unspecified or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved or ip_obj.is_multicast:
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
