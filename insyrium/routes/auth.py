import bcrypt
from datetime import datetime, timedelta
from flask import Blueprint, g, jsonify, request, redirect, url_for, current_app

from ..audit import log_audit
from ..extensions import db, limiter
from ..models import User
from ..network import get_client_ip, get_client_mac
from ..rbac import step_up_required, token_required
from ..schemas import (
    LoginSchema,
    OtpVerifySchema,
    RegisterSchema,
    StepUpSchema,
)
from ..security import enforce_csrf, set_csrf_cookie
from ..services import auth_service, otp_service, token_service

auth_bp = Blueprint("auth", __name__)

DUMMY_HASH = bcrypt.hashpw(b"dummy-password", bcrypt.gensalt(rounds=12))
REFRESH_COOKIE = "insyrium_refresh"

auth_bp.before_request(enforce_csrf)


def _login_key():
    email = ""
    try:
        email = (request.get_json(silent=True) or {}).get("email", "") or ""
    except Exception:
        pass
    return f"{email.strip().lower()}|{get_client_ip()}"


def _set_refresh_cookie(response, raw_token):
    max_age = current_app.config["REFRESH_TOKEN_DAYS"] * 86400
    response.set_cookie(
        REFRESH_COOKIE,
        raw_token,
        max_age=max_age,
        httponly=True,
        samesite="Lax",
        secure=request.is_secure,
        path="/",
    )
    return response


def _clear_refresh_cookie(response):
    response.delete_cookie(REFRESH_COOKIE, path="/")
    return response


def _complete_login(user):
    """Shared token-issuance path (Section 4.5)."""
    raw, _ = token_service.create_refresh_session(user, request)
    user.failed_attempts = 0
    user.locked_until = None
    # Keep login timestamps on the same clock as created_at / audit rows
    # (MySQL NOW() is server-local), so admin views show the real time.
    user.last_login_at = datetime.now()
    user.last_login_ip = get_client_ip()
    user.last_login_mac = get_client_mac()
    db.session.commit()
    log_audit(user.id, "login_success", target_id=user.id,
              metadata={"ip": user.last_login_ip, "mac": user.last_login_mac})
    response = jsonify(
        {
            "ok": True,
            "access_token": token_service.generate_access_token(user),
            "user": user.public_dict(),
        }
    )
    return _set_refresh_cookie(response, raw)


@auth_bp.route("/api/auth/register", methods=["POST"])
@limiter.limit("3 per 15 minutes", key_func=_login_key)
def register():
    if not current_app.config["ALLOW_REGISTRATION"]:
        return jsonify(error="Registration is currently disabled."), 403

    try:
        data = RegisterSchema().load(request.get_json(silent=True) or {})
    except Exception as exc:
        return jsonify(error="Validation failed", details=exc.messages), 400

    if User.query.filter_by(email=data["email"]).first():
        return jsonify(error="An account with this email already exists."), 409

    try:
        auth_service.register_user(
            data["email"],
            data["password"],
            data["name"],
            data["organization"],
            data.get("phone_number", ""),
            data.get("job_title", ""),
            data.get("department", ""),
            data.get("country", ""),
        )
    except Exception as exc:  # pragma: no cover
        current_app.logger.exception("registration failed")
        db.session.rollback()
        return jsonify(error="Something went wrong. Please try again."), 500

    try:
        from ..services import mail_service

        mail_service.send_alert(
            f"New account registered: {data['email']}",
            (
                f"A new account was created on the portal:\n\n"
                f"Name: {data['name']}\n"
                f"Email: {data['email']}\n"
                f"Organization: {data.get('organization') or '-'}\n"
                f"Job title: {data.get('job_title') or '-'}\n"
                f"Department: {data.get('department') or '-'}\n"
                f"Country: {data.get('country') or '-'}\n\n"
                "Review or manage this user from the admin dashboard."
            ),
            details=f"Sign-up from IP {get_client_ip()}.",
        )
    except Exception:  # never block registration on an alert
        current_app.logger.warning("Could not send registration alert", exc_info=True)

    return (
        jsonify(
            ok=True,
            message="Account created. Check your email to verify your address.",
        ),
        201,
    )


@auth_bp.route("/api/auth/verify-email", methods=["GET"])
def verify_email():
    token = request.args.get("token", "")
    if not token:
        return redirect(url_for("main.index", error="missing_token"))
    _, status = auth_service.verify_email_token(token)
    if status == "ok":
        return redirect(url_for("main.index", verified="1"))
    if status == "already":
        return redirect(url_for("main.index", verified="1"))
    return redirect(url_for("main.index", error="invalid_token"))


@auth_bp.route("/api/auth/login", methods=["POST"])
@limiter.limit("5 per 15 minutes", key_func=_login_key)
def login():
    try:
        data = LoginSchema().load(request.get_json(silent=True) or {})
    except Exception as exc:
        return jsonify(error="Validation failed", details=exc.messages), 400

    user = User.query.filter_by(email=data["email"]).first()

    # Lockout gate: check before touching the password so timing stays flat.
    if user and user.locked_until and user.locked_until > datetime.utcnow():
        minutes_left = max(
            1, int((user.locked_until - datetime.utcnow()).total_seconds() // 60)
        )
        return (
            jsonify(error=f"Account locked. Try again in {minutes_left} minute(s)."),
            429,
        )

    hash_to_check = user.password_hash.encode("utf-8") if user else DUMMY_HASH
    is_match = bcrypt.checkpw(data["password"].encode("utf-8"), hash_to_check)

    if not user or not is_match:
        if user:
            user.failed_attempts = (user.failed_attempts or 0) + 1
            if user.failed_attempts >= current_app.config["MAX_LOGIN_ATTEMPTS"]:
                user.locked_until = datetime.utcnow() + timedelta(
                    minutes=current_app.config["LOCKOUT_MINUTES"]
                )
                try:
                    from ..services import mail_service

                    mail_service.send_alert(
                        f"Account locked: {user.email}",
                        (
                            f"{user.email} was locked after "
                            f"{current_app.config['MAX_LOGIN_ATTEMPTS']} failed login attempts. "
                            f"Locked for {current_app.config['LOCKOUT_MINUTES']} minute(s).\n\n"
                            "Possible brute-force attempt — check the audit log."
                        ),
                        details=f"IP {get_client_ip()}, MAC {get_client_mac() or '-'}.",
                        level="critical",
                    )
                except Exception:  # never block login on an alert
                    current_app.logger.warning("Could not send lockout alert", exc_info=True)
            log_audit(
                user.id,
                "login_failed",
                target_id=user.id,
                metadata={
                    "ip": get_client_ip(),
                    "mac": get_client_mac(),
                    "ua": request.headers.get("User-Agent"),
                },
            )
            db.session.commit()
        # Always the same 401 — no user enumeration.
        return jsonify(error="Invalid email or password"), 401

    if user.status == "pending_verification":
        return jsonify(error="Please verify your email before logging in"), 403

    if user.status == "suspended":
        log_audit(
            user.id,
            "login_blocked_suspended",
            target_id=user.id,
            metadata={"ip": get_client_ip()},
        )
        db.session.commit()
        return (
            jsonify(error="Your account has been suspended. Contact support."),
            403,
        )

    payload = otp_service.start_challenge(user, request, purpose="login")
    log_audit(
        user.id,
        "otp_sent",
        target_id=user.id,
        metadata={"channel": payload["delivery_channel"], "ip": get_client_ip()},
    )
    db.session.commit()
    response = jsonify({"ok": True, **payload})
    return _set_refresh_cookie(response, ""), 202


@auth_bp.route("/api/auth/verify-otp", methods=["POST"])
@limiter.limit("5 per 15 minutes", key_func=_login_key)
def verify_otp():
    try:
        data = OtpVerifySchema().load(request.get_json(silent=True) or {})
    except Exception as exc:
        return jsonify(error="Validation failed", details=exc.messages), 400

    user = User.query.filter_by(email=data["email"]).first()
    ok, reason = otp_service.verify(data["email"], data["code"], purpose="login")
    if not ok:
        if user:
            log_audit(
                user.id,
                "otp_failed",
                target_id=user.id,
                metadata={"ip": get_client_ip(), "reason": reason},
            )
            db.session.commit()
        return jsonify(error="Invalid or expired code"), 401

    if user is None:
        return jsonify(error="Invalid or expired code"), 401

    log_audit(
        user.id,
        "otp_success",
        target_id=user.id,
        metadata={"ip": get_client_ip()},
    )
    return _complete_login(user)


@auth_bp.route("/api/auth/resend-otp", methods=["POST"])
@limiter.limit("2 per 15 minutes", key_func=_login_key)
def resend_otp():
    try:
        data = OtpVerifySchema().load(
            {**(request.get_json(silent=True) or {}), "code": "000000"}
        )
    except Exception as exc:
        return jsonify(error="Validation failed", details=exc.messages), 400

    user = User.query.filter_by(email=data["email"]).first()
    if user is None or user.status != "active":
        return jsonify(error="Invalid or expired code"), 401

    payload = otp_service.start_challenge(user, request, purpose="login")
    log_audit(
        user.id,
        "otp_resend",
        target_id=user.id,
        metadata={"channel": payload["delivery_channel"], "ip": get_client_ip()},
    )
    db.session.commit()
    return jsonify({"ok": True, **payload})


@auth_bp.route("/api/auth/refresh", methods=["POST"])
def refresh():
    raw = request.cookies.get(REFRESH_COOKIE, "")
    if not raw:
        return jsonify(error="No refresh session", code="no_session"), 401
    result = token_service.rotate_refresh(raw, request)
    if result is None:
        response = jsonify(error="Session expired", code="session_expired"), 401
        return _clear_refresh_cookie(response[0]), response[1]
    access_token, new_raw = result
    payload = token_service.decode_access_token(access_token)
    user = User.query.get(int(payload["sub"]))
    response = jsonify(
        {
            "ok": True,
            "access_token": access_token,
            "user": user.public_dict(),
        }
    )
    return _set_refresh_cookie(response, new_raw)


@auth_bp.route("/api/auth/logout", methods=["POST"])
def logout():
    raw = request.cookies.get(REFRESH_COOKIE, "")
    if raw:
        token_service.revoke_refresh(raw)
    response = jsonify(ok=True)
    return _clear_refresh_cookie(response)


@auth_bp.route("/api/auth/logout-all", methods=["POST"])
@token_required
def logout_all():
    from ..models import Session

    deleted = Session.query.filter_by(user_id=g.user.id).delete()
    db.session.commit()
    log_audit(
        g.user.id,
        "logout_all_devices",
        target_id=g.user.id,
        metadata={"devices": deleted, "ip": get_client_ip()},
    )
    response = jsonify(ok=True, devices_revoked=deleted)
    return _clear_refresh_cookie(response)


@auth_bp.route("/api/auth/me", methods=["GET"])
@token_required
def me():
    return jsonify(user=g.user.public_dict())


@auth_bp.route("/api/auth/profile/mfa", methods=["POST"])
@step_up_required
def toggle_mfa():
    body = request.get_json(silent=True) or {}
    enabled = bool(body.get("enabled"))

    g.user.mfa_enabled = enabled
    db.session.commit()
    log_audit(
        g.user.id,
        "mfa_toggled",
        target_id=g.user.id,
        metadata={"enabled": enabled, "ip": get_client_ip()},
    )
    return jsonify(ok=True, user=g.user.public_dict())


@auth_bp.route("/api/auth/change-password", methods=["POST"])
@token_required
def change_password():
    body = request.get_json(silent=True) or {}
    current = body.get("current") or ""
    new = body.get("new") or ""

    if not g.user.check_password(current):
        log_audit(
            g.user.id, "password_change_failed", target_id=g.user.id,
            metadata={"ip": get_client_ip(), "reason": "current_password"},
        )
        db.session.commit()
        return jsonify(error="Current password is incorrect."), 401

    if len(new) < 8 or not any(c.isupper() for c in new) \
            or not any(c.islower() for c in new) or not any(c.isdigit() for c in new):
        return (
            jsonify(error="New password must be 8+ characters with upper, lower and a digit."),
            400,
        )

    g.user.set_password(new)
    db.session.commit()
    log_audit(
        g.user.id, "password_changed", target_id=g.user.id,
        metadata={"ip": get_client_ip()},
    )
    return jsonify(ok=True, message="Password updated.")


@auth_bp.route("/api/auth/step-up", methods=["POST"])
@limiter.limit("5 per 15 minutes", key_func=_login_key)
def step_up():
    """Re-authentication for sensitive admin actions (Section 9.1.3)."""
    try:
        data = StepUpSchema().load(request.get_json(silent=True) or {})
    except Exception as exc:
        return jsonify(error="Validation failed", details=exc.messages), 400

    # Find the account by the signed access token instead of trusting the body.
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return jsonify(error="Missing access token"), 401
    try:
        payload = token_service.decode_access_token(header[7:])
    except Exception:
        return jsonify(error="Invalid access token"), 401
    user = User.query.get(int(payload["sub"]))
    if user is None:
        return jsonify(error="Account unavailable"), 401

    if not user.check_password(data["password"]):
        log_audit(
            user.id,
            "step_up_failed",
            target_id=user.id,
            metadata={"ip": get_client_ip(), "reason": "password"},
        )
        db.session.commit()
        return jsonify(error="Password did not match. Try again."), 401

    if user.mfa_enabled:
        if not data.get("otp"):
            payload2 = otp_service.start_challenge(user, request, purpose="step_up")
            log_audit(
                user.id,
                "otp_sent",
                target_id=user.id,
                metadata={"purpose": "step_up", "channel": payload2["delivery_channel"]},
            )
            db.session.commit()
            return jsonify({"ok": True, "otp_required": True, **payload2}), 202
        ok, _ = otp_service.verify(user.email, data["otp"], purpose="step_up")
        if not ok:
            log_audit(
                user.id,
                "step_up_failed",
                target_id=user.id,
                metadata={"ip": get_client_ip(), "reason": "otp"},
            )
            db.session.commit()
            return jsonify(error="Invalid or expired code"), 401

    log_audit(
        user.id,
        "step_up_success",
        target_id=user.id,
        metadata={"ip": get_client_ip()},
    )
    return jsonify(
        ok=True,
        step_up_token=token_service.generate_step_up_token(user),
    )
