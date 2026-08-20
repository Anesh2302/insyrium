"""Community security layer.

Covers the anti-abuse problems called out for Discord-style platforms:
  * phishing / scam links in messages          -> scan_links()
  * fake "nitro"/giveaway scams                -> scam_scan()
  * malware via fake attachments               -> check_attachment()
  * spam floods / duplicates                   -> spam helpers
"""

import re
from urllib.parse import urlparse

URL_RE = re.compile(r"(https?://[^\s<>\"]+|[a-z0-9.-]+\.(com|net|org|io|xyz|top|tk|ml|ga|cf|gq|info|cc|me)\b)", re.IGNORECASE)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "rb.gy", "cutt.ly", "is.gd", "shorturl.at", "buff.ly"}
SUSPICIOUS_TLDS = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "icu", "buzz", "loan", "win", "click", "review"}
DANGEROUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".com", ".scr", ".pif", ".vbs", ".vbe", ".js", ".jse",
    ".msi", ".msp", ".reg", ".ps1", ".apk", ".jar", ".sh", ".php", ".hta", ".cpl",
    ".wsf", ".wsh", ".docm", ".xlsm", ".pptm", ".msc", ".iso", ".dll",
}
ALLOWED_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".pdf", ".txt", ".md",
    ".csv", ".json", ".mp3", ".ogg", ".mp4", ".webm", ".zip", ".doc", ".docx",
    ".xls", ".xlsx", ".ppt", ".pptx",
}
MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024  # 5 MB

# ── Scam / phishing keyword heuristics (fake nitro, giveaways, crypto) ──
SCAM_PATTERNS = [
    re.compile(r"free\s+(discord\s+)?nitro", re.I),
    re.compile(r"nitro\s+(gift|code|generator)", re.I),
    re.compile(r"discord\.gift|steamcommunity\.com/gift|nitro\.app", re.I),
    re.compile(r"giveaway.{0,40}(claim|enter|win).{0,40}(link|click|now)", re.I),
    re.compile(r"(double|grow|multiply).{0,20}(your\s+)?(btc|bitcoin|eth|usdt|crypto)", re.I),
    re.compile(r"\b0x[a-fA-F0-9]{20,40}\b", re.I),  # crypto wallet address
    re.compile(r"you\s+have\s+won|winner.{0,20}(prize|reward)", re.I),
    re.compile(r"(login|verify|confirm).{0,20}(again|now).{0,20}(password|account)", re.I),
    re.compile(r"claim.{0,30}(reward|voucher|coupon|prize)", re.I),
    re.compile(r"\bdiscount\b.{0,20}\d{1,3}%\b", re.I),
]


def extract_links(text):
    return list(dict.fromkeys(URL_RE.findall(text or "")))


def _host_of(raw):
    match = URL_RE.match(raw or "")
    if not match:
        return None
    candidate = match.group(0)
    if "://" not in candidate:
        candidate = "http://" + candidate
    try:
        return urlparse(candidate).netloc.lower()
    except Exception:
        return None


def scan_links(text):
    """Return {'status': safe|flagged|blocked, 'hits': [...], 'hosts': [...]}."""
    hosts = [_host_of(h) for h in extract_links(text)]
    hosts = [h for h in hosts if h]

    reasons = []
    for h in hosts:
        base = h.replace("www.", "")
        if any(base == s or base.endswith("." + s) for s in SHORTENERS):
            reasons.append(f"link shortener ({h})")
        if base.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
            reasons.append(f"suspicious domain ({h})")
        if "discord" in base or "nitro" in base:
            if not any(b in base for b in ("discord.com", "discordapp.com")):
                reasons.append(f"lookalike domain ({h})")

    status = "safe"
    if reasons:
        status = "flagged"
    return {"status": status, "hits": reasons, "hosts": hosts}


def scam_scan(text):
    """Return (bool blocked, list reasons) for known scam wording."""
    hits = [p.pattern for p in SCAM_PATTERNS if p.search(text or "")]
    return bool(hits), hits


def check_attachment(filename, size):
    """Return (ok, reason). Blocks malware vectors + oversized files."""
    if not filename:
        return True, None
    name = filename.lower()
    for ext in DANGEROUS_EXTENSIONS:
        if name.endswith(ext):
            return False, f"File type '{ext}' is not allowed for safety."
    if size and size > MAX_ATTACHMENT_BYTES:
        return False, f"File is larger than {MAX_ATTACHMENT_BYTES // (1024 * 1024)} MB."
    ext = "." + name.rsplit(".", 1)[-1] if "." in name else ""
    if ext and ext not in ALLOWED_EXTENSIONS:
        return False, f"File type '{ext}' is not allowed."
    return True, None
