"""Client network detection: real client IP + best-effort MAC address.

Browsers never expose a MAC address over HTTP. For clients on the same
local network we resolve it from the server's ARP / neighbour table so
admins get a device identifier alongside the real IP. External clients
simply have no MAC and show as unknown.

IP resolution honours standard reverse-proxy headers (CF-Connecting-IP,
X-Real-IP, X-Forwarded-For) when present so a real IP is captured even
when the app sits behind nginx / Cloudflare.
"""

import ipaddress
import platform
import re
import subprocess

from flask import g, request

_PROXY_HEADERS = ("CF-Connecting-IP", "X-Real-IP", "X-Forwarded-For")


def get_client_ip():
    """Return the real client IP as seen by the server / proxy chain."""
    if "client_ip" in g:
        return g.client_ip
    for header in _PROXY_HEADERS:
        value = (request.headers.get(header) or "").strip()
        if not value:
            continue
        candidate = value.split(",")[0].strip()
        if _is_ip(candidate):
            g.client_ip = candidate
            return candidate
    g.client_ip = request.remote_addr or ""
    return g.client_ip


def get_client_mac(ip=None):
    """Best-effort MAC for a client IP, resolved once per request.

    Returns a normalized ``AA:BB:CC:DD:EE:FF`` string or ``None``.
    """
    if "client_mac" in g:
        return g.client_mac
    target = ip or get_client_ip()
    mac = _arp_lookup(target)
    g.client_mac = mac
    return mac


def _is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _normalize_mac(raw):
    digits = re.sub(r"[^0-9a-fA-F]", "", raw or "")
    if len(digits) != 12:
        return None
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2)).upper()


def _arp_lookup(ip):
    """Resolve ``ip`` → MAC from the ARP / neighbour table (LAN only)."""
    if not _is_ip(ip):
        return None
    system = platform.system().lower()
    try:
        if system == "windows":
            out = subprocess.run(
                ["arp", "-a"], capture_output=True, text=True, timeout=5
            ).stdout or ""
            pattern = re.compile(
                rf"\s+{re.escape(ip)}\s+([0-9a-fA-F][0-9a-fA-F-]{{16}})\s+"
            )
            for line in out.splitlines():
                match = pattern.search(line)
                if match:
                    return _normalize_mac(match.group(1))
        else:
            try:
                out = subprocess.run(
                    ["ip", "neigh"], capture_output=True, text=True, timeout=5
                ).stdout or ""
            except FileNotFoundError:
                out = ""
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 4 and parts[0] == ip and parts[2] == "lladdr":
                    return _normalize_mac(parts[3])
            if not out.strip():
                out = subprocess.run(
                    ["arp", "-an"], capture_output=True, text=True, timeout=5
                ).stdout or ""
                match = re.search(rf"\(({re.escape(ip)})\) at ([0-9a-fA-F:]+)", out)
                if match:
                    return _normalize_mac(match.group(2))
    except Exception:
        return None
    return None
