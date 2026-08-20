from datetime import datetime, timedelta

from flask import Blueprint, g, jsonify, request, current_app
from marshmallow import ValidationError

from ..audit import log_audit
from ..extensions import db
from ..models import (
    AdminScope,
    AppSetting,
    AuditLog,
    ContentResource,
    Enquiry,
    Role,
    Session,
    User,
)
from ..network import get_client_ip
from ..rbac import (
    require_role,
    require_supreme,
    step_up_required,
    token_required,
    RANK_ROLE,
)
from ..schemas import (
    ContentSchema,
    CreateAdminSchema,
    EditAdminSchema,
    EditUserSchema,
    EnquirySchema,
    SettingsSchema,
)
from ..security import enforce_csrf

admin_bp = Blueprint("admin", __name__)
admin_bp.before_request(enforce_csrf)

PRODUCTS = ("insyrium", "sape_tqm", "decisium", "mirads_builder")


def _set_scopes(user, products):
    AdminScope.query.filter_by(user_id=user.id).delete()
    for product in products:
        if product in PRODUCTS:
            db.session.add(AdminScope(user_id=user.id, product=product))
    db.session.commit()


def _scopes(user):
    return [s.product for s in user.scopes]


def _admin_alert(subject, body, details=None, level="warning"):
    try:
        from ..services import mail_service

        mail_service.send_alert(subject, body, details=details, level=level)
    except Exception:  # never fail an admin action on an alert
        current_app.logger.warning("Could not send admin alert", exc_info=True)


# ──────────────────────────────────────────────────────────
#  Public: contact form
# ──────────────────────────────────────────────────────────
@admin_bp.route("/api/public/enquiry", methods=["POST"])
def create_enquiry():
    try:
        data = EnquirySchema().load(request.get_json(silent=True) or {})
    except ValidationError as exc:
        return jsonify(error="Validation failed", details=exc.messages), 400

    enquiry = Enquiry(**data)
    db.session.add(enquiry)
    db.session.commit()
    return (
        jsonify(ok=True, message="Thanks! We'll get back to you shortly."),
        201,
    )


# ──────────────────────────────────────────────────────────
#  Dashboard overview
# ──────────────────────────────────────────────────────────
@admin_bp.route("/admin/stats", methods=["GET"])
@token_required
@require_role("admin_support")
def stats():
    # AuditLog.created_at is MySQL NOW() (DB-local time); use local now.
    day = datetime.now() - timedelta(hours=24)
    week = datetime.now() - timedelta(days=7)
    total = User.query.count()
    admins = User.query.join(Role).filter(Role.rank >= 1).count()
    published = ContentResource.query.filter_by(status="published").count()
    pending = ContentResource.query.filter_by(status="pending_review").count()
    new_enq = Enquiry.query.filter_by(status="new").count()
    logins = AuditLog.query.filter(
        AuditLog.action == "login_success", AuditLog.created_at >= day
    ).count()
    login_fails = AuditLog.query.filter(
        AuditLog.action == "login_failed", AuditLog.created_at >= day
    ).count()
    otp_fails = AuditLog.query.filter(
        AuditLog.action == "otp_failed", AuditLog.created_at >= day
    ).count()

    activity = [
        {"label": "Logins", "count": logins, "icon": "login"},
        {"label": "Failed logins", "count": login_fails, "icon": "shield"},
        {"label": "OTP failures", "count": otp_fails, "icon": "key"},
    ]

    weekly = [
        {"day": "Mon", "value": _daily(AuditLog, "login_success", 7, 0)},
        {"day": "Tue", "value": _daily(AuditLog, "login_success", 7, 1)},
        {"day": "Wed", "value": _daily(AuditLog, "login_success", 7, 2)},
        {"day": "Thu", "value": _daily(AuditLog, "login_success", 7, 3)},
        {"day": "Fri", "value": _daily(AuditLog, "login_success", 7, 4)},
        {"day": "Sat", "value": _daily(AuditLog, "login_success", 7, 5)},
        {"day": "Sun", "value": _daily(AuditLog, "login_success", 7, 6)},
    ]

    return jsonify(
        totals={
            "total_users": total,
            "active_users": User.query.filter_by(status="active").count(),
            "pending_users": User.query.filter_by(status="pending_verification").count(),
            "suspended_users": User.query.filter_by(status="suspended").count(),
            "admins": admins,
        },
        content={"published": published, "pending_review": pending, "all": ContentResource.query.count()},
        enquiries={"new": new_enq, "open": Enquiry.query.filter_by(status="open").count()},
        activity=activity,
        weekly=weekly,
    )


def _daily(model, action, days, back):
    # created_at is MySQL NOW() (DB-local time); use local now.
    start = datetime.now().replace(hour=0, minute=0, second=0) - timedelta(
        days=days - 1 - back
    )
    end = start + timedelta(days=1)
    return (
        model.query.filter(
            model.action == action,
            model.created_at >= start,
            model.created_at < end,
        ).count()
    )


# ──────────────────────────────────────────────────────────
#  User Management
# ──────────────────────────────────────────────────────────
@admin_bp.route("/admin/users", methods=["GET"])
@token_required
@require_role("admin_support")
def list_users():
    q = (request.args.get("q") or "").strip()
    status = request.args.get("status") or ""
    query = User.query
    if q:
        like = f"%{q}%"
        query = query.filter(
            db.or_(User.name.like(like), User.email.like(like), User.organization.like(like))
        )
    if status in ("active", "suspended", "pending_verification"):
        query = query.filter_by(status=status)
    users = query.order_by(User.id.desc()).limit(200).all()
    return jsonify(
        users=[
            {
                **u.public_dict(),
                "scopes": _scopes(u),
                "created_by": (
                    User.query.get(u.created_by).name if u.created_by else None
                ),
            }
            for u in users
        ]
    )


@admin_bp.route("/admin/users/<int:user_id>", methods=["PATCH"])
@token_required
@require_role("admin_platform")
def edit_user(user_id):
    if user_id == g.user.id:
        return jsonify(error="Use your profile to edit yourself."), 400
    target = User.query.get(user_id)
    if target is None:
        return jsonify(error="User not found"), 404
    if target.rank >= 3:
        return jsonify(error="Admins are managed in Admin Management."), 403

    try:
        data = EditUserSchema().load(request.get_json(silent=True) or {})
    except ValidationError as exc:
        return jsonify(error="Validation failed", details=exc.messages), 400

    before = {k: getattr(target, k) for k in data if data[k] is not None}
    if "name" in data and data["name"] is not None:
        target.name = data["name"].strip()
    if "organization" in data and data["organization"] is not None:
        target.organization = data["organization"].strip() or None
    if "status" in data and data["status"] is not None:
        target.status = data["status"]
    db.session.commit()

    log_audit(
        g.user.id,
        "user_updated",
        target_id=target.id,
        metadata={"before": before, "after": {k: getattr(target, k) for k in before}},
    )
    _admin_alert(
        f"User updated by {g.user.email}",
        f"{g.user.email} updated the account for {target.email} "
        f"(status: {before.get('status') or '-'} → {target.status}).",
        details=f"Changed fields: {', '.join(before) or 'none'}.",
    )
    return jsonify(ok=True, user=target.public_dict())


@admin_bp.route("/admin/users/<int:user_id>/role", methods=["PATCH"])
@token_required
@step_up_required
@require_supreme
def change_user_role(user_id):
    """Only the Supreme Admin can change a role (Section 9.1.2)."""
    target = User.query.get(user_id)
    if target is None:
        return jsonify(error="User not found"), 404
    if target.role_name == "supreme_admin":
        return jsonify(error="The Supreme Admin account cannot be changed."), 403

    body = request.get_json(silent=True) or {}
    new_role = (body.get("role") or "").strip()
    if new_role not in RANK_ROLE:
        return jsonify(error="Unknown role."), 400

    before = target.role.name
    target.role_id = Role.query.filter_by(name=new_role).first().id
    db.session.commit()
    log_audit(
        g.user.id,
        "role_changed",
        target_id=target.id,
        metadata={
            "before": before,
            "after": new_role,
            "actor_email": g.user.email,
        },
    )
    _admin_alert(
        f"Role changed: {target.email}",
        f"{g.user.email} changed {target.email}'s role from '{before}' to '{new_role}'.",
        level="critical",
    )
    return jsonify(ok=True, user=target.public_dict())


# ──────────────────────────────────────────────────────────
#  Active Sessions (IP / MAC / timing)
# ──────────────────────────────────────────────────────────
@admin_bp.route("/admin/sessions", methods=["GET"])
@token_required
@require_role("admin_platform")
def list_sessions():
    rows = (
        db.session.query(Session, User)
        .join(User, Session.user_id == User.id)
        .order_by(Session.created_at.desc())
        .limit(200)
        .all()
    )
    return jsonify(
        sessions=[
            {
                "id": s.id,
                "user_id": u.id,
                "user_name": u.name,
                "user_email": u.email,
                "role": u.role_name,
                "ip_address": s.ip_address or "",
                "mac_address": s.mac_address or "",
                "user_agent": s.user_agent or "",
                "created_at": s.created_at.isoformat() if s.created_at else None,
                "expires_at": s.expires_at.isoformat() if s.expires_at else None,
                "expired": bool(
                    s.expires_at and s.expires_at <= datetime.now()
                ),
            }
            for s, u in rows
        ]
    )


@admin_bp.route("/admin/sessions/<int:session_id>", methods=["DELETE"])
@token_required
@require_role("admin_platform")
def revoke_session(session_id):
    session = Session.query.get(session_id)
    if session is None:
        return jsonify(error="Session not found"), 404
    user = User.query.get(session.user_id)
    email = user.email if user else f"user#{session.user_id}"
    db.session.delete(session)
    db.session.commit()
    log_audit(
        g.user.id,
        "session_revoked",
        target_id=session.user_id,
        metadata={"email": email, "ip": get_client_ip()},
    )
    return jsonify(ok=True, message=f"Session revoked for {email}.")


# ──────────────────────────────────────────────────────────
#  Admin Management (Supreme only)
# ──────────────────────────────────────────────────────────
@admin_bp.route("/admin/admins", methods=["GET"])
@token_required
@require_supreme
def list_admins():
    admins = (
        User.query.join(Role)
        .filter(Role.rank >= 1)
        .order_by(Role.rank.desc(), User.id)
        .all()
    )
    return jsonify(
        admins=[
            {
                **u.public_dict(),
                "scopes": _scopes(u),
                "created_by": User.query.get(u.created_by).name if u.created_by else None,
            }
            for u in admins
        ]
    )


@admin_bp.route("/admin/admins", methods=["POST"])
@token_required
@step_up_required
@require_supreme
def create_admin():
    try:
        data = CreateAdminSchema().load(request.get_json(silent=True) or {})
    except ValidationError as exc:
        return jsonify(error="Validation failed", details=exc.messages), 400

    if User.query.filter_by(email=data["email"]).first():
        return jsonify(error="A user with this email already exists."), 409

    role = Role.query.filter_by(name=data["role"]).first()
    user = User(
        email=data["email"],
        name=data["name"],
        role_id=role.id,
        status="active",
        created_by=g.user.id,
        mfa_enabled=(
            AppSetting.get("default_mfa_for_admins", "true").lower() == "true"
        ),
        organization=data.get("organization") or None,
        phone_number=data.get("phone_number") or None,
        job_title=data.get("job_title") or None,
        department=data.get("department") or None,
        country=data.get("country") or None,
    )
    user.set_password(data["password"])
    db.session.add(user)
    db.session.commit()
    _set_scopes(user, data["products"])

    log_audit(
        g.user.id,
        "admin_created",
        target_id=user.id,
        metadata={"role": data["role"], "scopes": data["products"]},
    )
    from ..services import mail_service
    mail_service.send_welcome_email(
        user.email, user.name, role_label=data["role"].replace("_", " ")
    )
    _admin_alert(
        f"Admin created: {user.email}",
        f"{g.user.email} granted {user.email} the '{data['role']}' role "
        f"with scopes: {', '.join(data['products'])}.",
        level="critical",
    )
    return jsonify(ok=True, user=user.public_dict()), 201


@admin_bp.route("/admin/admins/<int:admin_id>", methods=["PATCH"])
@token_required
@step_up_required
@require_supreme
def edit_admin(admin_id):
    target = User.query.get(admin_id)
    if target is None:
        return jsonify(error="Admin not found"), 404
    if target.role_name == "supreme_admin":
        return jsonify(error="The Supreme Admin account cannot be edited here."), 403
    if target.rank < 1:
        return jsonify(error="This is a regular user account."), 400

    try:
        data = EditAdminSchema().load(request.get_json(silent=True) or {})
    except ValidationError as exc:
        return jsonify(error="Validation failed", details=exc.messages), 400

    before_role = target.role.name
    before_status = target.status
    before_scopes = _scopes(target)
    before_mfa = target.mfa_enabled

    if data.get("name"):
        target.name = data["name"]
    if data.get("role") and data["role"] != target.role.name:
        if data["role"] == "supreme_admin":
            return jsonify(error="You cannot grant the Supreme role."), 403
        target.role_id = Role.query.filter_by(name=data["role"]).first().id
    if data.get("status") and data["status"] != target.status:
        target.status = data["status"]
    if data.get("mfa_enabled") is not None:
        target.mfa_enabled = data["mfa_enabled"]
    for key in ("organization", "phone_number", "job_title", "department", "country"):
        if data.get(key) is not None:
            setattr(target, key, data[key] or None)
    db.session.commit()

    if data.get("products") is not None:
        _set_scopes(target, data["products"])

    log_audit(
        g.user.id,
        "admin_updated",
        target_id=target.id,
        metadata={
            "role_before": before_role,
            "role_after": target.role.name,
            "status_before": before_status,
            "status_after": target.status,
            "scopes_before": before_scopes,
            "scopes_after": _scopes(target),
            "mfa_before": before_mfa,
            "mfa_after": target.mfa_enabled,
        },
    )
    _admin_alert(
        f"Admin updated: {target.email}",
        f"{g.user.email} updated {target.email} "
        f"(role: {before_role} → {target.role.name}; "
        f"status: {before_status} → {target.status}).",
        level="critical",
    )
    return jsonify(ok=True, admin={**target.public_dict(), "scopes": _scopes(target)})


@admin_bp.route("/admin/admins/<int:admin_id>", methods=["DELETE"])
@token_required
@step_up_required
@require_supreme
def delete_admin(admin_id):
    target = User.query.get(admin_id)
    if target is None:
        return jsonify(error="Admin not found"), 404
    if target.role_name == "supreme_admin":
        return jsonify(error="The Supreme Admin account cannot be removed."), 403
    if target.rank < 1:
        return jsonify(error="This is a regular user account."), 400

    email = target.email
    db.session.delete(target)
    db.session.commit()
    log_audit(
        g.user.id,
        "admin_deleted",
        metadata={"email": email, "ip": get_client_ip()},
    )
    _admin_alert(
        f"Admin removed: {email}",
        f"{g.user.email} removed {email} from the admin team.",
        level="critical",
    )
    return jsonify(ok=True, message=f"{email} removed.")


# ──────────────────────────────────────────────────────────
#  Content Publishing (Section 9.2)
# ──────────────────────────────────────────────────────────
@admin_bp.route("/admin/content", methods=["GET"])
@token_required
@require_role("admin_content")
def list_content():
    status = request.args.get("status") or ""
    query = ContentResource.query
    if status in ("draft", "pending_review", "published", "rejected"):
        query = query.filter_by(status=status)
    items = query.order_by(ContentResource.id.desc()).limit(200).all()
    return jsonify(content=[c.to_dict() for c in items])


@admin_bp.route("/admin/content", methods=["POST"])
@token_required
@require_role("admin_content")
def create_content():
    try:
        data = ContentSchema().load(request.get_json(silent=True) or {})
    except ValidationError as exc:
        return jsonify(error="Validation failed", details=exc.messages), 400

    # Submissions from non-admin channels land in moderation (see enquiry flow);
    # admin-authored content goes straight to pending_review for a second admin.
    resource = ContentResource(
        type=data["type"],
        title=data["title"].strip(),
        body=data["body"],
        product=data["product"],
        file_url=data.get("file_url"),
        author_id=g.user.id,
        status="pending_review",
    )
    db.session.add(resource)
    db.session.commit()
    log_audit(
        g.user.id,
        "content_submitted",
        target_id=resource.id,
        metadata={"type": data["type"], "title": resource.title},
    )
    return jsonify(ok=True, content=resource.to_dict()), 201


@admin_bp.route("/admin/content/<int:item_id>/status", methods=["PATCH"])
@token_required
@require_role("admin_content")
def moderate_content(item_id):
    resource = ContentResource.query.get(item_id)
    if resource is None:
        return jsonify(error="Content not found"), 404

    body = request.get_json(silent=True) or {}
    new_status = body.get("status")
    if new_status not in ("published", "rejected", "draft"):
        return jsonify(error="Invalid status."), 400

    before = resource.status
    resource.status = new_status
    resource.moderator_id = g.user.id
    if new_status == "published":
        resource.published_at = datetime.now()
    db.session.commit()

    log_audit(
        g.user.id,
        "content_publish" if new_status == "published" else "content_moderated",
        target_id=resource.id,
        metadata={"before": before, "after": new_status, "title": resource.title},
    )
    return jsonify(ok=True, content=resource.to_dict())


# ──────────────────────────────────────────────────────────
#  Support Inbox (Section 9.1)
# ──────────────────────────────────────────────────────────
@admin_bp.route("/admin/enquiries", methods=["GET"])
@token_required
@require_role("admin_support")
def list_enquiries():
    status = request.args.get("status") or ""
    query = Enquiry.query
    if status in ("new", "open", "responded", "closed"):
        query = query.filter_by(status=status)
    items = query.order_by(Enquiry.id.desc()).limit(200).all()
    return jsonify(enquiries=[e.to_dict() for e in items])


@admin_bp.route("/admin/enquiries/<int:enquiry_id>/status", methods=["PATCH"])
@token_required
@require_role("admin_support")
def update_enquiry(enquiry_id):
    enquiry = Enquiry.query.get(enquiry_id)
    if enquiry is None:
        return jsonify(error="Enquiry not found"), 404
    body = request.get_json(silent=True) or {}
    new_status = body.get("status")
    if new_status not in ("new", "open", "responded", "closed"):
        return jsonify(error="Invalid status."), 400
    enquiry.status = new_status
    if new_status in ("responded", "closed"):
        enquiry.handled_by = g.user.id
    db.session.commit()
    log_audit(
        g.user.id,
        "enquiry_updated",
        target_id=enquiry.id,
        metadata={"status": new_status},
    )
    return jsonify(ok=True, enquiry=enquiry.to_dict())


# ──────────────────────────────────────────────────────────
#  Audit Logs (Section 9.3)
# ──────────────────────────────────────────────────────────
@admin_bp.route("/admin/audit-logs", methods=["GET"])
@token_required
@require_role("admin_platform")
def audit_logs():
    query = AuditLog.query
    action = request.args.get("action") or ""
    actor_id = request.args.get("actor_id") or ""
    date_from = request.args.get("from") or ""
    date_to = request.args.get("to") or ""

    if action:
        query = query.filter_by(action=action)
    if actor_id:
        query = query.filter_by(actor_id=int(actor_id))
    if date_from:
        try:
            query = query.filter(
                AuditLog.created_at >= datetime.fromisoformat(date_from)
            )
        except ValueError:
            pass
    if date_to:
        try:
            query = query.filter(
                AuditLog.created_at <= datetime.fromisoformat(date_to)
            )
        except ValueError:
            pass

    logs = query.order_by(AuditLog.id.desc()).limit(200).all()

    def _actor_name(aid):
        u = User.query.get(aid)
        return f"{u.name} <{u.email}>" if u else f"user#{aid}"

    return jsonify(
        logs=[
            {
                **log.to_dict(),
                "actor_name": _actor_name(log.actor_id),
                "actor_email": _actor_email(log.actor_id),
            }
            for log in logs
        ]
    )


def _actor_email(aid):
    u = User.query.get(aid)
    return u.email if u else None


# ──────────────────────────────────────────────────────────
#  System Config / Billing (Supreme only)
# ──────────────────────────────────────────────────────────
@admin_bp.route("/admin/config", methods=["GET"])
@token_required
@require_supreme
def get_config():
    return jsonify(
        config={
            "portal_name": AppSetting.get("portal_name", current_app.config["PORTAL_NAME"]),
            "allow_registration": AppSetting.get("allow_registration", "true").lower() == "true",
            "maintenance_mode": AppSetting.get("maintenance_mode", "false").lower() == "true",
            "default_mfa_for_admins": AppSetting.get("default_mfa_for_admins", "true").lower() == "true",
            "alert_email": AppSetting.get("alert_email", ""),
        }
    )


@admin_bp.route("/admin/config", methods=["PATCH"])
@token_required
@step_up_required
@require_supreme
def update_config():
    try:
        data = SettingsSchema().load(request.get_json(silent=True) or {})
    except ValidationError as exc:
        return jsonify(error="Validation failed", details=exc.messages), 400

    before = {}
    for key, value in data.items():
        if value is None:
            continue
        before[key] = AppSetting.get(key)
        AppSetting.set(key, str(value).lower() if isinstance(value, bool) else value, g.user.id)

    log_audit(
        g.user.id,
        "config_updated",
        metadata={"before": before, "after": {k: str(v) for k, v in data.items() if v is not None}},
    )
    changes = "\n".join(
        f"  {k}: {v}" for k, v in data.items() if v is not None
    )
    _admin_alert(
        f"Settings changed by {g.user.email}",
        f"Portal settings were updated:\n{changes}" if changes else "Portal settings were updated.",
    )
    return jsonify(ok=True, message="Settings saved.")


@admin_bp.route("/admin/billing", methods=["GET"])
@token_required
@require_supreme
def billing():
    now = datetime.utcnow()
    invoices = [
        {
            "id": "INV-2026-0084",
            "description": "Insyrium Portal — enterprise license",
            "amount": 4900.00,
            "status": "paid",
            "due": (now - timedelta(days=12)).strftime("%Y-%m-%d"),
        },
        {
            "id": "INV-2026-0085",
            "description": "SAPE-TQM module — yearly renewal",
            "amount": 2400.00,
            "status": "paid",
            "due": (now - timedelta(days=3)).strftime("%Y-%m-%d"),
        },
        {
            "id": "INV-2026-0086",
            "description": "Decisium analytics add-on",
            "amount": 1200.00,
            "status": "pending",
            "due": (now + timedelta(days=11)).strftime("%Y-%m-%d"),
        },
        {
            "id": "INV-2026-0087",
            "description": "MIRADS Builder storage upgrade",
            "amount": 350.00,
            "status": "overdue",
            "due": (now - timedelta(days=5)).strftime("%Y-%m-%d"),
        },
    ]
    total_paid = sum(i["amount"] for i in invoices if i["status"] == "paid")
    total_pending = sum(i["amount"] for i in invoices if i["status"] in ("pending", "overdue"))
    return jsonify(
        billing={
            "invoices": invoices,
            "totals": {
                "paid": round(total_paid, 2),
                "pending": round(total_pending, 2),
                "this_month": round(total_paid + total_pending, 2),
            },
        }
    )
