"""CSRF double-submit protection (stateless) + security headers."""

import secrets

from flask import request, jsonify, g

CSRF_COOKIE = "insyrium_csrf"


def csrf_token():
    if CSRF_COOKIE in request.cookies:
        return request.cookies[CSRF_COOKIE]
    return secrets.token_urlsafe(32)


def set_csrf_cookie(response):
    token = csrf_token()
    response.set_cookie(
        CSRF_COOKIE,
        token,
        max_age=60 * 60 * 24 * 7,
        httponly=False,
        samesite="Lax",
        secure=request.is_secure,
        path="/",
    )
    return response


def enforce_csrf():
    """Run as before_request on API blueprints: mutating calls must echo the CSRF cookie."""
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return None
    header = request.headers.get("X-CSRF-Token", "")
    cookie = request.cookies.get(CSRF_COOKIE, "")
    if not cookie or not secrets.compare_digest(header, cookie):
        return jsonify(error="CSRF token missing or invalid", code="csrf_error"), 403
    return None


def security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(self), microphone=(self), geolocation=()")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob: https:; "
        "media-src 'self' blob: mediastream:; "
        "connect-src 'self' ws: wss:",
    )
    if request.is_secure:
        response.headers.setdefault(
            "Strict-Transport-Security",
            f"max-age={g.get('hsts_seconds', 31536000)}; includeSubDomains",
        )
    return response
