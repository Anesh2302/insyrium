"""JWT access tokens + hashed refresh-session rows (Sections 4.5 / 5)."""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

import jwt
from flask import current_app

from ..extensions import db
from ..models import Session, User
from ..network import get_client_ip, get_client_mac


def _now():
    return datetime.now(timezone.utc)


def generate_access_token(user):
    now = _now()
    payload = {
        "sub": str(user.id),
        "role": user.role_name,
        "rank": user.rank,
        "jti": secrets.token_hex(8),
        "iat": now,
        "exp": now + timedelta(minutes=current_app.config["ACCESS_TOKEN_MINUTES"]),
    }
    return jwt.encode(
        payload, current_app.config["JWT_SECRET_KEY"], algorithm="HS256"
    )


def decode_access_token(token):
    return jwt.decode(
        token,
        current_app.config["JWT_SECRET_KEY"],
        algorithms=["HS256"],
    )


def generate_step_up_token(user, minutes=5):
    now = _now()
    payload = {
        "sub": str(user.id),
        "scope": "step_up",
        "jti": secrets.token_hex(8),
        "iat": now,
        "exp": now + timedelta(minutes=minutes),
    }
    return jwt.encode(
        payload, current_app.config["JWT_SECRET_KEY"], algorithm="HS256"
    )


def hash_token(raw):
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def create_refresh_session(user, request):
    raw = secrets.token_urlsafe(48)
    session = Session(
        user_id=user.id,
        refresh_token_hash=hash_token(raw),
        user_agent=(request.headers.get("User-Agent") or "")[:255],
        ip_address=get_client_ip(),
        mac_address=get_client_mac(),
        expires_at=datetime.now()
        + timedelta(days=current_app.config["REFRESH_TOKEN_DAYS"]),
    )
    db.session.add(session)
    db.session.commit()
    return raw, session


def rotate_refresh(raw, request):
    """Return a fresh (access_token, raw_refresh) or None if invalid."""
    token_hash = hash_token(raw)
    session = (
        Session.query.filter_by(refresh_token_hash=token_hash)
        .order_by(Session.id.desc())
        .first()
    )
    if session is None:
        return None
    if session.expires_at is None:
        db.session.delete(session)
        db.session.commit()
        return None
    expires_at = session.expires_at
    if expires_at.tzinfo is not None:
        expires_at = expires_at.replace(tzinfo=None)
    if expires_at <= datetime.now():
        db.session.delete(session)
        db.session.commit()
        return None

    user = User.query.get(session.user_id)
    if user is None or user.status != "active":
        return None

    db.session.delete(session)
    new_raw, _ = create_refresh_session(user, request)
    return generate_access_token(user), new_raw


def revoke_refresh(raw):
    """Delete one refresh session row (Section 4.7)."""
    token_hash = hash_token(raw)
    session = (
        Session.query.filter_by(refresh_token_hash=token_hash)
        .order_by(Session.id.desc())
        .first()
    )
    if session is not None:
        db.session.delete(session)
        db.session.commit()
