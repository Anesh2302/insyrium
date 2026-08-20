"""Server-side OTP codes (Section 4.4).

Codes are generated with secrets, stored as SHA-256 hashes, delivered over the
channel already on file, and usable exactly once within 5 minutes.
"""

import hashlib
import secrets
from datetime import datetime, timedelta

from flask import current_app

from ..extensions import db
from ..models import OtpCode, User
from . import mail_service


def _hash(code):
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def _masked(email):
    if "@" not in email:
        return email
    local, domain = email.split("@", 1)
    if len(local) <= 1:
        masked_local = local + "*"
    elif len(local) == 2:
        masked_local = local[0] + "*"
    else:
        masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
    return f"{masked_local}@{domain}"


def start_challenge(user, request, purpose="login"):
    """Generate, store and deliver a code. Returns a response-ready dict."""
    code = str(secrets.randbelow(1_000_000)).zfill(6)
    channel = "email"
    if user.phone_verified and user.phone_number:
        channel = "sms"

    # Invalidate any previous open codes for this user + purpose.
    OtpCode.query.filter_by(user_id=user.id, purpose=purpose).delete()

    otp = OtpCode(
        user_id=user.id,
        code_hash=_hash(code),
        purpose=purpose,
        channel=channel,
        attempts=0,
        expires_at=datetime.utcnow()
        + timedelta(seconds=current_app.config["OTP_EXPIRY_SECONDS"]),
    )
    db.session.add(otp)
    db.session.commit()

    if channel == "email":
        mail_service.send_otp_email(user.email, code, purpose)
    else:  # SMS gateway placeholder (Twilio etc.)
        print(f"[SMS · DEV CONSOLE] to {user.phone_number}: code {code}", flush=True)
        mail_service.send_otp_email(user.email, code, purpose)

    return {
        "otp_required": True,
        "purpose": purpose,
        "delivery_channel": channel,
        "masked_target": _masked(user.email) if channel == "email" else _mask_phone(user.phone_number),
        "expires_in": current_app.config["OTP_EXPIRY_SECONDS"],
        "max_attempts": current_app.config["OTP_MAX_ATTEMPTS"],
    }


def _mask_phone(phone):
    phone = phone or ""
    if len(phone) <= 4:
        return "*" * len(phone)
    return "*" * (len(phone) - 4) + phone[-4:]


def verify(email, code, purpose="login"):
    """Verify a submitted code. Deletes on success; increments attempts on failure."""
    user = User.query.filter_by(email=email.lower().strip()).first()
    if user is None:
        return False, "invalid"

    otp = (
        OtpCode.query.filter_by(user_id=user.id, purpose=purpose)
        .order_by(OtpCode.id.desc())
        .first()
    )
    if otp is None:
        return False, "invalid"

    if otp.expires_at is None or otp.expires_at < datetime.utcnow():
        db.session.delete(otp)
        db.session.commit()
        return False, "expired"

    if otp.attempts >= current_app.config["OTP_MAX_ATTEMPTS"]:
        db.session.delete(otp)
        db.session.commit()
        return False, "exhausted"

    if not secrets.compare_digest(otp.code_hash, _hash(code.strip())):
        otp.attempts += 1
        db.session.commit()
        return False, "invalid"

    db.session.delete(otp)
    db.session.commit()
    return True, "ok"
