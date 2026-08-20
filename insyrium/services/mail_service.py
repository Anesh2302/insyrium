"""Mail delivery with a console fallback.

When no SMTP credentials are configured, verification links and OTP codes are
printed to the server console so the whole flow can be exercised locally.
"""

import os
from datetime import datetime, timedelta

from flask import current_app
from flask_mail import Message

from ..extensions import mail


def _smtp_configured(app=None):
    app = app or current_app
    return bool(
        app.config.get("MAIL_USERNAME")
        and app.config.get("MAIL_PASSWORD")
    )


def _console(to, subject, body):
    line = "=" * 72
    print("\n" + line, flush=True)
    print(f"  [MAIL · DEV CONSOLE] to: {to}", flush=True)
    print(f"  subject: {subject}", flush=True)
    print(line, flush=True)
    print(body, flush=True)
    print(line + "\n", flush=True)


def _portal_name():
    try:
        return current_app.config.get("PORTAL_NAME", "Insyrium Portal")
    except Exception:
        return "Insyrium Portal"


def _template(title, paragraphs, button_label, button_url, code=None, footer=""):
    """Minimal, inbox-safe HTML email with optional OTP code display."""
    accent = "#5865f2"
    paras = "".join(f'<p style="margin:0 0 14px;font-size:15px;line-height:1.6;color:#334155">{p}</p>'
                    for p in paragraphs)
    code_block = (
        f'<div style="text-align:center;margin:22px 0;padding:18px;border:2px dashed {accent};'
        f'border-radius:10px;background:#eef2ff;font-family:monospace;font-size:34px;'
        f'font-weight:700;letter-spacing:8px;color:{accent}">{code}</div>'
        if code else ""
    )
    button = (
        f'<div style="text-align:center;margin:20px 0">'
        f'<a href="{button_url}" style="background:{accent};color:#ffffff;text-decoration:none;'
        f'padding:12px 28px;border-radius:8px;font-weight:600;display:inline-block">{button_label}</a>'
        f'</div>'
        if button_url else ""
    )
    return f"""<!doctype html><html><body style="margin:0;padding:0;background:#f1f5f9">
<div style="max-width:520px;margin:0 auto;padding:28px 20px">
  <div style="background:#ffffff;border-radius:14px;padding:26px 28px;border:1px solid #e2e8f0">
    <div style="font-size:20px;font-weight:700;color:#0f172a;margin-bottom:16px">◈ {title}</div>
    {paras}
    {code_block}
    {button}
    <p style="font-size:12px;color:#94a3b8;margin:18px 0 0">{footer}</p>
  </div>
  <p style="text-align:center;font-size:11px;color:#94a3b8;margin:16px 0 0">{_portal_name()}</p>
</div></body></html>"""


def send(to, subject, body, html=None):
    """Send an email, or print to console in development."""
    if _smtp_configured():
        try:
            msg = Message(
                subject,
                recipients=[to],
                body=body,
                html=html,
            )
            mail.send(msg)
            return True
        except Exception as exc:  # pragma: no cover - depends on external SMTP
            current_app.logger.warning("SMTP send failed, falling back to console: %s", exc)
            _console(to, subject, body)
            return False

    _console(to, subject, body)
    return True


def send_verification_email(email, token):
    verify_url = f"{_base_url()}/api/auth/verify-email?token={token}"
    subject = "Confirm your Insyrium Portal email"
    body = (
        "Welcome to Insyrium Portal.\n\n"
        "Confirm your email address by opening the link below (valid for 24 hours):\n\n"
        f"{verify_url}\n\n"
        "If you didn't create this account, you can ignore this message."
    )
    html = _template(
        "Confirm your email",
        [
            "Welcome to Insyrium Portal — you're almost in.",
            "Confirm your email address by clicking the button below (valid for 24 hours):",
        ],
        "Verify my email",
        verify_url,
        footer="If you didn't create this account, you can ignore this message.",
    )
    send(email, subject, body, html)


def send_welcome_email(email, name, role_label="member"):
    """A warm welcome email for users and admins after their account is live."""
    portal = _portal_name()
    subject = f"Welcome to {portal}, {name}!"
    dashboard = f"{_base_url()}/dashboard"
    body = (
        f"Hi {name},\n\n"
        f"Your {portal} account is ready.\n\n"
        f"Role: {role_label}\n"
        "You can sign in any time from the link below:\n\n"
        f"{dashboard}\n\n"
        "If you ever lose access or notice anything unusual, contact the platform team."
    )
    html = _template(
        f"Welcome to {portal}",
        [
            f"Hi {name}, your {role_label} account is ready to use.",
            "You can sign in any time from the link below:",
        ],
        "Go to my dashboard",
        dashboard,
        footer="If you didn't create this account, contact the platform team.",
    )
    send(email, subject, body, html)


def send_otp_email(email, code, purpose="login"):
    portal = _portal_name()
    label = purpose.replace("_", " ")
    ttl = int(current_app.config.get("OTP_EXPIRY_SECONDS", 300))
    expires_local = datetime.now() + timedelta(seconds=ttl)
    stamp = expires_local.strftime("%H:%M")
    subject = f"{portal} — your {label} code ({stamp})"
    body = (
        f"Your one-time code is: {code}\n\n"
        f"It expires at {stamp} and can be used exactly once — only for the latest {label} attempt. "
        "Codes from older messages are no longer valid.\n\n"
        "If you didn't request it, you can ignore this message."
    )
    html = _template(
        f"Your {label} code",
        [
            f"Use the code below to finish signing in. It expires at <b>{stamp}</b> and can only be "
            "used once, for the latest sign-in attempt. Codes from older messages are no longer valid.",
        ],
        "Confirm",
        None,
        code=code,
        footer=f"This code expires at {stamp}. If you didn't request this code, you can ignore this message.",
    )
    send(email, subject, body, html)


def _alert_recipient():
    """Resolve the admin alert inbox: dashboard 'Alert email' → ALERT_EMAIL env → MAIL_DEFAULT_SENDER."""
    try:
        from ..models import AppSetting

        email = AppSetting.get("alert_email", "") or AppSetting.get("alert-email", "")
        if email:
            return email
    except Exception:  # never block alerting on a settings lookup
        pass
    return os.getenv("ALERT_EMAIL") or current_app.config.get("MAIL_DEFAULT_SENDER")


def send_alert(subject, body, details=None, level="warning"):
    """Admin alert → console in dev, email if SMTP configured.

    Recipient priority: dashboard 'Alert email' setting, then ALERT_EMAIL env,
    then MAIL_DEFAULT_SENDER. Returns True when a message was handed off.
    """
    to = _alert_recipient()
    if not to:
        return False
    paragraphs = [body]
    if details:
        paragraphs.append(details)
    html = _template(
        f"[{level.upper()}] {subject}",
        paragraphs,
        None,
        None,
        footer=f"This is an automated security/operations alert from {_portal_name()}.",
    )
    return send(to, f"[ALERT] {subject}", body, html)


def _base_url():
    return current_app.config.get("BASE_URL", "http://127.0.0.1:5000")
