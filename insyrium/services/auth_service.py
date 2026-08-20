"""Registration and email verification (Section 4.1)."""

from datetime import timedelta

from flask import current_app
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from ..extensions import db
from ..models import User, Role
from . import mail_service

_EMAIL_TTL_HOURS = 24


def _serializer():
    return URLSafeTimedSerializer(
        current_app.config["SECRET_KEY"], salt="email-verification"
    )


def register_user(
    email,
    password,
    name,
    organization,
    phone_number="",
    job_title="",
    department="",
    country="",
):
    """Create a pending_verification user and email a verification link."""
    user_role = Role.query.filter_by(name="user").first()
    user = User(
        email=email.lower().strip(),
        name=name.strip(),
        organization=(organization or "").strip() or None,
        phone_number=(phone_number or "").strip() or None,
        job_title=(job_title or "").strip() or None,
        department=(department or "").strip() or None,
        country=(country or "").strip() or None,
        role_id=user_role.id if user_role else 1,
        status="pending_verification",
        mfa_enabled=True,
    )
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    token = _serializer().dumps(user.email)
    mail_service.send_verification_email(user.email, token)
    return user


def verify_email_token(token):
    try:
        email = _serializer().loads(token, max_age=_EMAIL_TTL_HOURS * 3600)
    except SignatureExpired:
        return None, "expired"
    except BadSignature:
        return None, "invalid"

    user = User.query.filter_by(email=email).first()
    if user is None:
        return None, "invalid"
    if user.status == "active":
        return user, "already"
    user.status = "active"
    db.session.commit()
    from . import community as community_service
    community_service.ensure_user_in_default(user)
    mail_service.send_welcome_email(user.email, user.name, role_label=user.role_name.replace("_", " "))
    return user, "ok"
