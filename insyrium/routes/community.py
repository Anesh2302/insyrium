"""Insyrium Community — API routes.

Discord-style servers, channels, polling chat, moderation, encrypted-at-rest
DMs, notifications, plus an admin-visible documentation trail written to the
project docs/ folder for every security-relevant event.
"""

import base64
import hashlib
import json
import re
import secrets
from datetime import datetime, timedelta
from urllib.parse import urlparse

from cryptography.fernet import Fernet
from flask import Blueprint, g, jsonify, request, send_file, current_app
from marshmallow import ValidationError
from sqlalchemy import or_

from ..audit import log_audit
from ..extensions import db
from .. import realtime
from ..models import (
    Channel,
    CommunityServer,
    DmMessage,
    DmThread,
    Message,
    Notification,
    Report,
    ServerBan,
    ServerMember,
    ServerRole,
    User,
    Perm,
    MessageReaction,
    Thread,
    ChannelCategory,
    PinnedMessage,
    CustomEmoji,
    ChannelPermissionOverride,
    UserStatus,
    ScheduledEvent,
    AutoModRule,
    Webhook,
    Sticker,
    ServerTemplate,
    GroupDmThread,
    GroupDmMember,
    GroupDmMessage,
    ScreenShare,
    StageChannel,
    ServerBoost,
    RichPresence,
    ForumPost,
    ForumReply,
    VerificationLevel,
    Bot,
    OnboardingStep,
    RaidLog,
    NotificationPreference,
    SessionFingerprint,
)
from ..rbac import require_role, token_required
from ..schemas import Schema, fields, validate
from ..security import enforce_csrf
from ..services import community as cc
from ..services import docs_service
from ..services.scanner import (
    check_attachment,
    scam_scan,
    scan_links,
    ALLOWED_EXTENSIONS,
)

community_bp = Blueprint("community", __name__)
community_bp.before_request(enforce_csrf)

MESSAGE_LIMIT = 2000


# ── Validation ──────────────────────────────────────────────────────────
class ServerCreate(Schema):
    name = fields.Str(required=True, validate=validate.Length(min=2, max=80))
    description = fields.Str(load_default="", validate=validate.Length(max=500))


class ChannelCreate(Schema):
    name = fields.Str(required=True, validate=validate.Regexp(r"^[a-z0-9-]{2,40}$"))
    kind = fields.Str(load_default="text", validate=validate.OneOf(["text", "voice"]))
    topic = fields.Str(load_default="", validate=validate.Length(max=300))
    slow_mode_seconds = fields.Int(load_default=0, validate=validate.Range(min=0, max=3600))


class ChannelEdit(Schema):
    name = fields.Str(validate=validate.Regexp(r"^[a-z0-9-]{2,40}$"))
    topic = fields.Str(validate=validate.Length(max=300))
    slow_mode_seconds = fields.Int(validate=validate.Range(min=0, max=3600))


class MessageCreate(Schema):
    body = fields.Str(required=True, validate=validate.Length(min=1, max=MESSAGE_LIMIT))


class RoleCreate(Schema):
    name = fields.Str(required=True, validate=validate.Length(min=2, max=50))
    color = fields.Str(load_default="#99aab5", validate=validate.Regexp(r"^#[0-9a-fA-F]{6}$"))
    permissions = fields.List(fields.Str(), load_default=[])


class ModAction(Schema):
    reason = fields.Str(load_default="", validate=validate.Length(max=500))
    until_minutes = fields.Int(load_default=0, validate=validate.Range(min=1, max=10080))


class ReportCreate(Schema):
    reason = fields.Str(required=True, validate=validate.Length(min=3, max=500))


class ServerSettings(Schema):
    description = fields.Str(validate=validate.Length(max=500))
    retention_days = fields.Int(validate=validate.Range(min=0, max=3650))


class ReactionAdd(Schema):
    emoji = fields.Str(required=True, validate=validate.Length(min=1, max=32))


class ThreadCreate(Schema):
    name = fields.Str(required=True, validate=validate.Length(min=1, max=100))
    channel_id = fields.Int(required=True)


class CategoryCreate(Schema):
    name = fields.Str(required=True, validate=validate.Length(min=1, max=50))
    position = fields.Int(load_default=0)


class EventCreate(Schema):
    name = fields.Str(required=True, validate=validate.Length(min=1, max=100))
    description = fields.Str(load_default="", validate=validate.Length(max=500))
    channel_id = fields.Int(load_default=None)
    start_at = fields.Str(required=True)
    end_at = fields.Str(load_default=None)
    location = fields.Str(load_default="", validate=validate.Length(max=200))


class AutoModCreate(Schema):
    name = fields.Str(required=True, validate=validate.Length(min=1, max=50))
    trigger_type = fields.Str(required=True, validate=validate.OneOf(["keyword", "spam", "mention_flood", "link_filter"]))
    trigger_value = fields.Str(load_default="")
    action_type = fields.Str(required=True, validate=validate.OneOf(["block", "flag", "mute", "warn"]))
    action_duration_minutes = fields.Int(load_default=0)


class WebhookCreate(Schema):
    name = fields.Str(required=True, validate=validate.Length(min=1, max=80))
    channel_id = fields.Int(required=True)


class StickerCreate(Schema):
    name = fields.Str(required=True, validate=validate.Length(min=1, max=50))
    url = fields.Str(required=True)
    tags = fields.Str(load_default="", validate=validate.Length(max=128))


class TemplateCreate(Schema):
    name = fields.Str(required=True, validate=validate.Length(min=1, max=80))
    description = fields.Str(load_default="", validate=validate.Length(max=500))


class MessageForward(Schema):
    message_id = fields.Int(required=True)
    channel_id = fields.Int(required=True)


class GroupDmCreate(Schema):
    name = fields.Str(load_default="Group Chat", validate=validate.Length(min=1, max=80))
    user_ids = fields.List(fields.Int(), required=True)


class StageCreate(Schema):
    channel_id = fields.Int(required=True)
    topic = fields.Str(load_default="", validate=validate.Length(max=200))


class BoostTier(Schema):
    tier = fields.Int(required=True, validate=validate.OneOf([1, 2, 3]))


class ForumPostCreate(Schema):
    title = fields.Str(required=True, validate=validate.Length(min=1, max=100))
    body = fields.Str(required=True, validate=validate.Length(min=1, max=10000))
    tags = fields.Str(load_default="", validate=validate.Length(max=200))


class ForumReplyCreate(Schema):
    body = fields.Str(required=True, validate=validate.Length(min=1, max=5000))


class BotCreate(Schema):
    name = fields.Str(required=True, validate=validate.Length(min=1, max=80))
    description = fields.Str(load_default="", validate=validate.Length(max=500))
    permissions = fields.List(fields.Str(), load_default=[])


class OnboardingStepCreate(Schema):
    title = fields.Str(required=True, validate=validate.Length(min=1, max=80))
    description = fields.Str(load_default="", validate=validate.Length(max=300))
    required_role_id = fields.Int(load_default=None)
    step_order = fields.Int(load_default=0)


# ── Encryption at rest for DMs ─────────────────────────────────────────
def _fernet():
    secret = current_app.config["SECRET_KEY"].encode("utf-8")
    key = base64.urlsafe_b64encode(hashlib.sha256(secret).digest())
    return Fernet(key)


def _encrypt(plain):
    return _fernet().encrypt(plain.encode("utf-8")).decode("utf-8")


def _decrypt(token):
    return _fernet().decrypt(token.encode("utf-8")).decode("utf-8")


# ── Helpers ─────────────────────────────────────────────────────────────
def _server_or_404(sid):
    server = CommunityServer.query.get(sid)
    if server is None:
        return None
    return server


def _require_perm(server, perm):
    """Load the caller's membership and enforce a permission bit."""
    member = cc.member_of(server.id)
    if member is None or member.is_suspended:
        return None, jsonify(error="You are not a member of this server."), 403
    if not cc.can(member, perm):
        return None, jsonify(error="You do not have permission to do this."), 403
    return member, None, None


def _member_count(server_id):
    return ServerMember.query.filter_by(server_id=server_id).count()


def _generate_embed(url):
    """Return a JSON string with a basic rich embed for a URL."""
    return json.dumps({
        "title": "",
        "description": "",
        "url": url,
        "image": "",
    })


def _urls_in_text(text):
    """Extract URLs from message text."""
    return re.findall(r'https?://[^\s<>\"\')]+', text)


# ── In-memory RSVP store (replace with a table later) ───────────────────
_rsvps = {}  # event_id -> list of user_ids


# ── Servers ─────────────────────────────────────────────────────────────
@community_bp.route("/api/community/servers", methods=["GET"])
@token_required
def list_servers():
    cc.ensure_default_community(join_user=g.user)
    mine = (
        db.session.query(CommunityServer)
        .join(ServerMember, ServerMember.server_id == CommunityServer.id)
        .filter(ServerMember.user_id == g.user.id)
        .order_by(CommunityServer.name)
        .all()
    )
    return jsonify(
        servers=[s.to_dict(_member_count(s.id)) for s in mine]
    )


@community_bp.route("/api/community/servers", methods=["POST"])
@token_required
def create_server():
    try:
        data = ServerCreate().load(request.get_json(silent=True) or {})
    except ValidationError as exc:
        return jsonify(error="Validation failed", details=exc.messages), 400

    slug = data["name"].lower().strip().replace(" ", "-")[:80]
    base_slug = slug
    n = 1
    while CommunityServer.query.filter_by(slug=slug).first():
        n += 1
        slug = f"{base_slug}-{n}"

    server = CommunityServer(
        name=data["name"].strip(),
        slug=slug,
        description=data["description"].strip(),
        invite_code=secrets.token_urlsafe(8),
        owner_id=g.user.id,
        retention_days=0,
    )
    db.session.add(server)
    db.session.flush()

    everyone = ServerRole(
        server_id=server.id,
        name="@everyone",
        rank=0,
        permissions=Perm.DEFAULT_MEMBER,
        is_default=True,
    )
    owner_role = ServerRole(
        server_id=server.id,
        name="Owner",
        rank=100,
        permissions=Perm.OWNER,
        color="#f9a825",
    )
    db.session.add_all([everyone, owner_role])
    db.session.flush()

    db.session.add(ServerMember(server_id=server.id, user_id=g.user.id, role_id=owner_role.id))
    db.session.add(
        Channel(
            server_id=server.id,
            name="general",
            kind="text",
            topic="Welcome! Read the rules and say hello.",
            created_by=g.user.id,
            position=0,
        )
    )
    db.session.commit()

    log_audit(g.user.id, "community_server_created", target_id=server.id,
              metadata={"name": server.name})
    docs_service.write_event(
        "server_created",
        {"actor_id": g.user.id, "target": server.id, "name": server.name},
        actor_id=g.user.id,
    )
    return jsonify(ok=True, server=server.to_dict(1)), 201


@community_bp.route("/api/community/servers/<int:sid>", methods=["GET"])
@token_required
def get_server(sid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    member = cc.member_of(server.id)
    if member is None:
        return jsonify(error="You are not a member of this server."), 403

    channels = Channel.query.filter_by(server_id=server.id).order_by(Channel.position, Channel.id).all()
    roles = ServerRole.query.filter_by(server_id=server.id).order_by(ServerRole.rank.desc()).all()
    members = (
        ServerMember.query.filter_by(server_id=server.id, is_suspended=False)
        .order_by(ServerMember.joined_at)
        .limit(200)
        .all()
    )
    return jsonify(
        server=server.to_dict(_member_count(server.id)),
        channels=[c.to_dict() for c in channels],
        roles=[r.to_dict() for r in roles],
        members=[m.to_dict() for m in members],
        me=member.to_dict(),
        my_permissions=cc.effective_permissions(member),
    )


@community_bp.route("/api/community/invite/<code>", methods=["GET", "POST"])
@token_required
def join_by_invite(code):
    server = CommunityServer.query.filter_by(invite_code=code).first()
    if server is None:
        return jsonify(error="That invite is invalid or expired."), 404

    if request.method == "POST":
        existing = cc.member_of(server.id)
        if existing:
            return jsonify(ok=True, server_id=server.id)
        banned = ServerBan.query.filter_by(server_id=server.id, user_id=g.user.id).first()
        if banned:
            return jsonify(error="You are banned from this server."), 403
        default_role = ServerRole.query.filter_by(server_id=server.id, is_default=True).first()
        db.session.add(
            ServerMember(
                server_id=server.id,
                user_id=g.user.id,
                role_id=default_role.id if default_role else None,
            )
        )
        db.session.commit()
        log_audit(g.user.id, "community_server_joined", target_id=server.id,
                  metadata={"name": server.name})
        docs_service.write_event(
            "member_joined",
            {"actor_id": g.user.id, "target": server.id, "server": server.name},
            actor_id=g.user.id,
        )
        return jsonify(ok=True, server_id=server.id)
    return jsonify(server=server.to_dict(_member_count(server.id)))


@community_bp.route("/api/community/servers/<int:sid>/leave", methods=["POST"])
@token_required
def leave_server(sid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    member = cc.member_of(server.id)
    if member is None:
        return jsonify(error="You are not a member."), 403
    if server.owner_id == g.user.id:
        return jsonify(error="The owner cannot leave. Transfer ownership or delete."), 400
    db.session.delete(member)
    db.session.commit()
    docs_service.write_event(
        "member_left",
        {"actor_id": g.user.id, "target": server.id},
        actor_id=g.user.id,
    )
    return jsonify(ok=True)


@community_bp.route("/api/community/servers/<int:sid>/settings", methods=["PATCH"])
@token_required
def server_settings(sid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    _, err, status = _require_perm(server, Perm.MANAGE_SERVER)
    if err:
        return err, status
    try:
        data = ServerSettings().load(request.get_json(silent=True) or {})
    except ValidationError as exc:
        return jsonify(error="Validation failed", details=exc.messages), 400
    if data.get("description") is not None:
        server.description = data["description"].strip()
    if data.get("retention_days") is not None:
        server.retention_days = data["retention_days"]
    db.session.commit()
    docs_service.write_event(
        "server_settings",
        {"actor_id": g.user.id, "target": server.id, "changes": data},
        actor_id=g.user.id,
    )
    return jsonify(ok=True, server=server.to_dict(_member_count(server.id)))


# ── Channels ────────────────────────────────────────────────────────────
@community_bp.route("/api/community/servers/<int:sid>/channels", methods=["POST"])
@token_required
def create_channel(sid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    _, err, status = _require_perm(server, Perm.MANAGE_CHANNELS)
    if err:
        return err, status
    try:
        data = ChannelCreate().load(request.get_json(silent=True) or {})
    except ValidationError as exc:
        return jsonify(error="Validation failed", details=exc.messages), 400

    count = Channel.query.filter_by(server_id=server.id).count()
    channel = Channel(
        server_id=server.id,
        name=data["name"],
        kind=data["kind"],
        topic=data["topic"],
        slow_mode_seconds=data["slow_mode_seconds"],
        created_by=g.user.id,
        position=count,
    )
    db.session.add(channel)
    db.session.commit()
    docs_service.write_event(
        "channel_created",
        {"actor_id": g.user.id, "target": server.id, "channel": channel.name},
        actor_id=g.user.id,
    )
    return jsonify(ok=True, channel=channel.to_dict()), 201


@community_bp.route("/api/community/channels/<int:cid>", methods=["PATCH"])
@token_required
def edit_channel(cid):
    channel = Channel.query.get(cid)
    if channel is None:
        return jsonify(error="Channel not found"), 404
    _, err, status = _require_perm(_server_or_404(channel.server_id), Perm.MANAGE_CHANNELS)
    if err:
        return err, status
    try:
        data = ChannelEdit().load(request.get_json(silent=True) or {})
    except ValidationError as exc:
        return jsonify(error="Validation failed", details=exc.messages), 400
    for key in ("name", "topic", "slow_mode_seconds"):
        if data.get(key) is not None:
            setattr(channel, key, data[key])
    db.session.commit()
    return jsonify(ok=True, channel=channel.to_dict())


@community_bp.route("/api/community/channels/<int:cid>", methods=["DELETE"])
@token_required
def delete_channel(cid):
    channel = Channel.query.get(cid)
    if channel is None:
        return jsonify(error="Channel not found"), 404
    _, err, status = _require_perm(_server_or_404(channel.server_id), Perm.MANAGE_CHANNELS)
    if err:
        return err, status
    docs_service.write_event(
        "channel_deleted",
        {"actor_id": g.user.id, "target": channel.server_id, "channel": channel.name},
        actor_id=g.user.id,
    )
    db.session.delete(channel)
    db.session.commit()
    return jsonify(ok=True)


# ── Messages ────────────────────────────────────────────────────────────
@community_bp.route("/api/community/channels/<int:cid>/messages", methods=["GET"])
@token_required
def list_messages(cid):
    channel = Channel.query.get(cid)
    if channel is None:
        return jsonify(error="Channel not found"), 404
    member = cc.member_of(channel.server_id)
    if member is None or not cc.can(member, Perm.READ):
        return jsonify(error="You cannot view this channel."), 403

    after = request.args.get("after", type=int, default=0)
    query = Message.query.filter(
        Message.channel_id == cid,
        Message.deleted_at.is_(None),
        Message.flagged.is_(False),
    )
    if after:
        query = query.filter(Message.id > after)
    msgs = query.order_by(Message.id.asc()).limit(200).all()
    return jsonify(messages=[m.to_dict() for m in msgs])


@community_bp.route("/api/community/channels/<int:cid>/messages", methods=["POST"])
@token_required
def send_message(cid):
    channel = Channel.query.get(cid)
    if channel is None:
        return jsonify(error="Channel not found"), 404
    member = cc.member_of(channel.server_id)
    if member is None:
        return jsonify(error="You are not a member of this server."), 403
    if not cc.can(member, Perm.SEND):
        return jsonify(error="You do not have permission to send messages."), 403
    if cc.is_muted(member):
        return jsonify(error="You are muted in this server."), 403

    try:
        data = MessageCreate().load(request.get_json(silent=True) or {})
    except ValidationError as exc:
        return jsonify(error="Validation failed", details=exc.messages), 400

    text = data["body"].strip()
    if not text:
        return jsonify(error="Message is empty."), 400

    # ── Security scans ──
    blocked_scam, scam_hits = scam_scan(text)
    link_info = scan_links(text)
    blocked_link = link_info["status"] == "blocked"

    # ── Spam gate ──
    spam, spam_reason = cc.is_spam(g.user.id, channel.server_id, cid, text)
    if spam:
        return jsonify(error=f"Blocked: {spam_reason}"), 429

    blocked = bool(blocked_scam or blocked_link)
    link_status = link_info["status"]

    message = Message(
        server_id=channel.server_id,
        channel_id=cid,
        author_id=g.user.id,
        body=text,
        link_status=link_status,
        flagged=blocked,
        attachment_name=request.form.get("attachment_name"),
        attachment_size=request.form.get("attachment_size", type=int),
    )

    if blocked:
        # Auto-block: do not deliver to the channel. Record + alert + notify sender.
        db.session.add(message)
        db.session.commit()
        reason = "; ".join(scam_hits + link_info["hits"]) or "blocked content"
        cc.notify(
            g.user.id,
            "mod",
            "Your message was blocked",
            f"Security filter removed your message in #{channel.name}: {reason}",
            f"/community/{channel.server_id}",
        )
        docs_service.write_event(
            "message_blocked",
            {
                "actor_id": g.user.id,
                "target": channel.server_id,
                "channel": channel.name,
                "reason": reason,
            },
            actor_id=g.user.id,
        )
        return jsonify(
            ok=False,
            blocked=True,
            error=f"Message blocked by security filter ({reason}).",
        ), 200

    db.session.add(message)
    db.session.flush()

    # ── Rich embed generation ──
    urls = _urls_in_text(text)
    if urls:
        embeds = [_generate_embed(u) for u in urls[:3]]
        message.embed_json = json.dumps(embeds)
        db.session.flush()

    # ── Mention notifications ──
    mentioned = _mention_users(channel.server_id, text, exclude=g.user.id)
    for target in mentioned:
        cc.notify(
            target,
            "mention",
            f"You were mentioned in #{channel.name}",
            text[:120],
            f"/community/{channel.server_id}?channel={cid}",
        )

    db.session.commit()

    # Realtime: push the persisted message to everyone viewing this channel.
    realtime.emit_channel_message(message.to_dict())

    return jsonify(ok=True, message=message.to_dict()), 201


def _mention_users(server_id, text, exclude=None):
    names = [u.strip() for u in text.split("@") if u.strip()]
    members = ServerMember.query.filter_by(server_id=server_id).all()
    targets = []
    for m in members:
        if m.user_id == exclude:
            continue
        if m.nickname and f"@{m.nickname}" in text:
            targets.append(m.user_id)
        elif m.user and f"@{m.user.name}" in text:
            targets.append(m.user_id)
    return list(set(targets))


@community_bp.route("/api/community/messages/<int:mid>", methods=["PATCH"])
@token_required
def edit_message(mid):
    message = Message.query.get(mid)
    if message is None or message.deleted_at:
        return jsonify(error="Message not found"), 404
    member = cc.member_of(message.server_id)
    can_mod = member and cc.can(member, Perm.MANAGE_MESSAGES)
    if not can_mod and message.author_id != g.user.id:
        return jsonify(error="You cannot edit this message."), 403
    try:
        data = MessageCreate().load(request.get_json(silent=True) or {})
    except ValidationError as exc:
        return jsonify(error="Validation failed", details=exc.messages), 400
    text = data["body"].strip()
    blocked_scam, _hits = scam_scan(text)
    link_info = scan_links(text)
    if blocked_scam or link_info["status"] == "blocked":
        return jsonify(error="Edited message blocked by security filter."), 400
    message.body = text
    message.edited_at = datetime.utcnow()
    message.link_status = link_info["status"]
    message.flagged = bool(blocked_scam)
    db.session.commit()
    return jsonify(ok=True, message=message.to_dict())


@community_bp.route("/api/community/messages/<int:mid>", methods=["DELETE"])
@token_required
def delete_message(mid):
    message = Message.query.get(mid)
    if message is None or message.deleted_at:
        return jsonify(error="Message not found"), 404
    member = cc.member_of(message.server_id)
    can_mod = member and cc.can(member, Perm.MANAGE_MESSAGES)
    if not can_mod and message.author_id != g.user.id:
        return jsonify(error="You cannot delete this message."), 403
    message.deleted_at = datetime.utcnow()
    db.session.commit()
    realtime.emit_channel_delete(message.channel_id, message.id)
    docs_service.write_event(
        "message_deleted",
        {"actor_id": g.user.id, "target": message.server_id, "message_id": mid},
        actor_id=g.user.id,
    )
    return jsonify(ok=True)


@community_bp.route("/api/community/messages/<int:mid>/report", methods=["POST"])
@token_required
def report_message(mid):
    message = Message.query.get(mid)
    if message is None or message.deleted_at:
        return jsonify(error="Message not found"), 404
    try:
        data = ReportCreate().load(request.get_json(silent=True) or {})
    except ValidationError as exc:
        return jsonify(error="Validation failed", details=exc.messages), 400
    existing = Report.query.filter_by(
        message_id=mid, reporter_id=g.user.id, status="new"
    ).first()
    if existing:
        return jsonify(error="You already reported this message."), 409
    report = Report(
        server_id=message.server_id,
        channel_id=message.channel_id,
        message_id=mid,
        reporter_id=g.user.id,
        reason=data["reason"],
    )
    db.session.add(report)
    db.session.commit()
    # Notify moderators of the server.
    _notify_moderators(message.server_id, "A message was reported", data["reason"])
    docs_service.write_event(
        "message_reported",
        {
            "actor_id": g.user.id,
            "target": message.server_id,
            "message_id": mid,
            "reason": data["reason"],
        },
        actor_id=g.user.id,
    )
    return jsonify(ok=True, report=report.to_dict()), 201


def _notify_moderators(server_id, title, body):
    members = ServerMember.query.filter_by(server_id=server_id).all()
    for m in members:
        if cc.can(m, Perm.MODERATE):
            cc.notify(m.user_id, "mod", title, body, f"/community/{server_id}")


# ── Voice presence (realtime-backed) ─────────────────────────────────────
@community_bp.route("/api/community/channels/<int:cid>/voice", methods=["POST"])
@token_required
def voice_join(cid):
    channel = Channel.query.get(cid)
    if channel is None or channel.kind != "voice":
        return jsonify(error="Not a voice channel"), 400
    member = cc.member_of(channel.server_id)
    if member is None or not cc.can(member, Perm.VIEW):
        return jsonify(error="You cannot join this channel."), 403
    realtime.voice_add(cid, g.user.id)
    realtime.broadcast_voice(channel.server_id)
    return jsonify(ok=True, joined=len(realtime.voice_members(cid)))


@community_bp.route("/api/community/channels/<int:cid>/voice", methods=["DELETE"])
@token_required
def voice_leave(cid):
    channel = Channel.query.get(cid)
    if channel is not None:
        realtime.voice_remove(cid, g.user.id)
        realtime.broadcast_voice(channel.server_id)
    return jsonify(ok=True)


# ── Roles & permissions ─────────────────────────────────────────────────
@community_bp.route("/api/community/servers/<int:sid>/roles", methods=["POST"])
@token_required
def create_role(sid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    _, err, status = _require_perm(server, Perm.MANAGE_ROLES)
    if err:
        return err, status
    try:
        data = RoleCreate().load(request.get_json(silent=True) or {})
    except ValidationError as exc:
        return jsonify(error="Validation failed", details=exc.messages), 400
    bits = 0
    for name in data["permissions"]:
        bits |= Perm.NAMES.get(name, 0)
    role = ServerRole(
        server_id=server.id,
        name=data["name"].strip(),
        rank=10,
        permissions=bits or Perm.DEFAULT_MEMBER,
        color=data["color"],
    )
    db.session.add(role)
    db.session.commit()
    docs_service.write_event(
        "role_created",
        {"actor_id": g.user.id, "target": server.id, "role": role.name, "permissions": data["permissions"]},
        actor_id=g.user.id,
    )
    return jsonify(ok=True, role=role.to_dict()), 201


@community_bp.route("/api/community/servers/<int:sid>/roles/<int:rid>", methods=["PATCH"])
@token_required
def edit_role(sid, rid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    _, err, status = _require_perm(server, Perm.MANAGE_ROLES)
    if err:
        return err, status
    role = ServerRole.query.filter_by(id=rid, server_id=sid).first()
    if role is None:
        return jsonify(error="Role not found"), 404
    try:
        data = RoleCreate().load(request.get_json(silent=True) or {})
    except ValidationError as exc:
        return jsonify(error="Validation failed", details=exc.messages), 400
    role.name = data["name"].strip()
    role.color = data["color"]
    bits = 0
    for name in data["permissions"]:
        bits |= Perm.NAMES.get(name, 0)
    role.permissions = bits or role.permissions
    db.session.commit()
    docs_service.write_event(
        "role_updated",
        {"actor_id": g.user.id, "target": server.id, "role": role.name},
        actor_id=g.user.id,
    )
    return jsonify(ok=True, role=role.to_dict())


@community_bp.route("/api/community/servers/<int:sid>/roles/<int:rid>", methods=["DELETE"])
@token_required
def delete_role(sid, rid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    _, err, status = _require_perm(server, Perm.MANAGE_ROLES)
    if err:
        return err, status
    role = ServerRole.query.filter_by(id=rid, server_id=sid).first()
    if role is None:
        return jsonify(error="Role not found"), 404
    if role.is_default:
        return jsonify(error="The default role cannot be deleted."), 400
    ServerMember.query.filter_by(role_id=rid).update({"role_id": None})
    db.session.delete(role)
    db.session.commit()
    return jsonify(ok=True)


@community_bp.route("/api/community/servers/<int:sid>/members/<int:uid>/role", methods=["POST"])
@token_required
def assign_role(sid, uid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    _, err, status = _require_perm(server, Perm.MANAGE_ROLES)
    if err:
        return err, status
    target = ServerMember.query.filter_by(server_id=sid, user_id=uid).first()
    if target is None:
        return jsonify(error="Member not found"), 404
    body = request.get_json(silent=True) or {}
    role = ServerRole.query.filter_by(id=body.get("role_id"), server_id=sid).first()
    if role is None:
        return jsonify(error="Role not found"), 400
    target.role_id = role.id
    db.session.commit()
    docs_service.write_event(
        "role_assigned",
        {"actor_id": g.user.id, "target": uid, "server": sid, "role": role.name},
        actor_id=g.user.id,
    )
    return jsonify(ok=True, member=target.to_dict())


# ── Moderation ──────────────────────────────────────────────────────────
@community_bp.route("/api/community/servers/<int:sid>/members/<int:uid>/mute", methods=["POST"])
@token_required
def mute_member(sid, uid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    _, err, status = _require_perm(server, Perm.MUTE)
    if err:
        return err, status
    try:
        data = ModAction().load(request.get_json(silent=True) or {})
    except ValidationError as exc:
        return jsonify(error="Validation failed", details=exc.messages), 400
    target = ServerMember.query.filter_by(server_id=sid, user_id=uid).first()
    if target is None:
        return jsonify(error="Member not found"), 404
    target.muted_until = datetime.utcnow() + timedelta(minutes=data["until_minutes"])
    db.session.commit()
    cc.notify(uid, "mod", "You were muted",
              f"You were muted in {server.name} for {data['until_minutes']} min: {data['reason']}",
              f"/community/{sid}")
    docs_service.write_event(
        "member_muted",
        {"actor_id": g.user.id, "target": uid, "server": sid,
         "until_minutes": data["until_minutes"], "reason": data["reason"]},
        actor_id=g.user.id,
    )
    return jsonify(ok=True, member=target.to_dict())


@community_bp.route("/api/community/servers/<int:sid>/members/<int:uid>/unmute", methods=["POST"])
@token_required
def unmute_member(sid, uid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    _, err, status = _require_perm(server, Perm.MUTE)
    if err:
        return err, status
    target = ServerMember.query.filter_by(server_id=sid, user_id=uid).first()
    if target is None:
        return jsonify(error="Member not found"), 404
    target.muted_until = None
    db.session.commit()
    return jsonify(ok=True, member=target.to_dict())


@community_bp.route("/api/community/servers/<int:sid>/members/<int:uid>/kick", methods=["POST"])
@token_required
def kick_member(sid, uid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    _, err, status = _require_perm(server, Perm.KICK)
    if err:
        return err, status
    target = ServerMember.query.filter_by(server_id=sid, user_id=uid).first()
    if target is None:
        return jsonify(error="Member not found"), 404
    if uid == server.owner_id:
        return jsonify(error="You cannot kick the owner."), 400
    if uid == g.user.id:
        return jsonify(error="You cannot kick yourself."), 400
    db.session.delete(target)
    db.session.commit()
    cc.notify(uid, "mod", "You were kicked", f"You were kicked from {server.name}.", f"/community/{sid}")
    docs_service.write_event(
        "member_kicked",
        {"actor_id": g.user.id, "target": uid, "server": sid},
        actor_id=g.user.id,
    )
    return jsonify(ok=True)


@community_bp.route("/api/community/servers/<int:sid>/members/<int:uid>/ban", methods=["POST"])
@token_required
def ban_member(sid, uid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    _, err, status = _require_perm(server, Perm.BAN)
    if err:
        return err, status
    try:
        data = ModAction().load(request.get_json(silent=True) or {})
    except ValidationError as exc:
        return jsonify(error="Validation failed", details=exc.messages), 400
    if uid == server.owner_id:
        return jsonify(error="You cannot ban the owner."), 400
    target = ServerMember.query.filter_by(server_id=sid, user_id=uid).first()
    if target:
        db.session.delete(target)
    if ServerBan.query.filter_by(server_id=sid, user_id=uid).first() is None:
        db.session.add(
            ServerBan(
                server_id=sid,
                user_id=uid,
                reason=data["reason"],
                banned_by=g.user.id,
            )
        )
    db.session.commit()
    cc.notify(uid, "mod", "You were banned", f"You were banned from {server.name}: {data['reason']}", f"/community/{sid}")
    docs_service.write_event(
        "member_banned",
        {"actor_id": g.user.id, "target": uid, "server": sid, "reason": data["reason"]},
        actor_id=g.user.id,
    )
    return jsonify(ok=True)


@community_bp.route("/api/community/servers/<int:sid>/members/<int:uid>/unban", methods=["POST"])
@token_required
def unban_member(sid, uid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    _, err, status = _require_perm(server, Perm.BAN)
    if err:
        return err, status
    ban = ServerBan.query.filter_by(server_id=sid, user_id=uid).first()
    if ban is None:
        return jsonify(error="Not banned"), 404
    db.session.delete(ban)
    db.session.commit()
    return jsonify(ok=True)


@community_bp.route("/api/community/servers/<int:sid>/reports", methods=["GET"])
@token_required
def list_reports(sid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    _, err, status = _require_perm(server, Perm.MODERATE)
    if err:
        return err, status
    reports = Report.query.filter_by(server_id=sid).order_by(Report.id.desc()).limit(100).all()
    return jsonify(reports=[r.to_dict() for r in reports])


@community_bp.route("/api/community/reports/<int:rid>/resolve", methods=["POST"])
@token_required
def resolve_report(rid):
    report = Report.query.get(rid)
    if report is None:
        return jsonify(error="Report not found"), 404
    _, err, status = _require_perm(_server_or_404(report.server_id), Perm.MODERATE)
    if err:
        return err, status
    report.status = "resolved"
    report.handled_by = g.user.id
    db.session.commit()
    docs_service.write_event(
        "report_resolved",
        {"actor_id": g.user.id, "report_id": rid, "server": report.server_id},
        actor_id=g.user.id,
    )
    return jsonify(ok=True)


@community_bp.route("/api/community/reports/<int:rid>", methods=["DELETE"])
@token_required
def dismiss_report(rid):
    report = Report.query.get(rid)
    if report is None:
        return jsonify(error="Report not found"), 404
    _, err, status = _require_perm(_server_or_404(report.server_id), Perm.MODERATE)
    if err:
        return err, status
    report.status = "dismissed"
    report.handled_by = g.user.id
    db.session.commit()
    return jsonify(ok=True)


# ── Notifications ───────────────────────────────────────────────────────
@community_bp.route("/api/community/notifications", methods=["GET"])
@token_required
def list_notifications():
    unread = request.args.get("unread", type=int, default=0)
    q = Notification.query.filter_by(user_id=g.user.id)
    if unread:
        q = q.filter(Notification.read_at.is_(None))
    items = q.order_by(Notification.id.desc()).limit(50).all()
    return jsonify(notifications=[n.to_dict() for n in items])


@community_bp.route("/api/community/notifications/read", methods=["POST"])
@token_required
def mark_notifications_read():
    Notification.query.filter_by(user_id=g.user.id, read_at=None).update(
        {"read_at": datetime.utcnow()}
    )
    db.session.commit()
    return jsonify(ok=True)


# ── Poll (lightweight realtime) ─────────────────────────────────────────
@community_bp.route("/api/community/poll", methods=["GET"])
@token_required
def poll():
    unread = Notification.query.filter_by(user_id=g.user.id, read_at=None).count()
    voice = realtime.voice_snapshot()
    return jsonify(unread_notifications=unread, voice=voice)


# ── DMs (encrypted at rest) ─────────────────────────────────────────────
def _thread_for(a, b):
    a, b = sorted([a, b])
    return DmThread.query.filter_by(user_a=a, user_b=b).first()


@community_bp.route("/api/community/dms", methods=["GET"])
@token_required
def list_dms():
    threads = (
        DmThread.query.filter(or_(DmThread.user_a == g.user.id, DmThread.user_b == g.user.id))
        .order_by(DmThread.id.desc())
        .all()
    )
    out = []
    for t in threads:
        other = t.user_b if t.user_a == g.user.id else t.user_a
        user = User.query.get(other)
        out.append(
            {
                "id": t.id,
                "user_id": other,
                "username": user.name if user else "unknown",
                "email": user.email if user else "",
            }
        )
    return jsonify(threads=out)


@community_bp.route("/api/community/dms", methods=["POST"])
@token_required
def start_dm():
    body = request.get_json(silent=True) or {}
    try:
        other = int(body.get("user_id") or 0)
    except (TypeError, ValueError):
        other = 0
    if not other or other == g.user.id:
        return jsonify(error="Invalid user."), 400
    thread = _thread_for(g.user.id, other)
    if thread is None:
        a, b = sorted([g.user.id, other])
        thread = DmThread(user_a=a, user_b=b)
        db.session.add(thread)
        db.session.commit()
    return jsonify(ok=True, thread_id=thread.id)


@community_bp.route("/api/community/dms/<int:tid>/messages", methods=["GET"])
@token_required
def dm_messages(tid):
    thread = DmThread.query.get(tid)
    if thread is None or g.user.id not in (thread.user_a, thread.user_b):
        return jsonify(error="Thread not found"), 404
    after = request.args.get("after", type=int, default=0)
    q = DmMessage.query.filter_by(thread_id=tid)
    if after:
        q = q.filter(DmMessage.id > after)
    msgs = q.order_by(DmMessage.id.asc()).limit(200).all()
    out = []
    for m in msgs:
        try:
            body = _decrypt(m.ciphertext)
        except Exception:
            body = "[unreadable]"
        out.append(
            {
                "id": m.id,
                "sender_id": m.sender_id,
                "body": body,
                "created_at": m.created_at.isoformat() if m.created_at else None,
            }
        )
    return jsonify(messages=out)


@community_bp.route("/api/community/dms/<int:tid>/messages", methods=["POST"])
@token_required
def send_dm(tid):
    thread = DmThread.query.get(tid)
    if thread is None or g.user.id not in (thread.user_a, thread.user_b):
        return jsonify(error="Thread not found"), 404
    try:
        data = MessageCreate().load(request.get_json(silent=True) or {})
    except ValidationError as exc:
        return jsonify(error="Validation failed", details=exc.messages), 400
    text = data["body"].strip()
    blocked_scam, scam_hits = scam_scan(text)
    link_info = scan_links(text)
    if blocked_scam or link_info["status"] == "blocked":
        cc.notify(g.user.id, "mod", "DM blocked", "Your private message was blocked by the security filter.",
                  "/community/dms")
        return jsonify(error="Message blocked by security filter."), 400

    other = thread.user_b if thread.user_a == g.user.id else thread.user_a
    m = DmMessage(thread_id=tid, sender_id=g.user.id, ciphertext=_encrypt(text))
    db.session.add(m)
    db.session.commit()
    realtime.emit_dm_message(tid, {"id": m.id, "sender_id": m.sender_id,
                                    "body": text,
                                    "created_at": m.created_at.isoformat() if m.created_at else None})
    cc.notify(other, "dm", "New private message", text[:120], "/community/dms")
    return jsonify(ok=True, message={"id": m.id, "sender_id": m.sender_id,
                                      "body": text,
                                      "created_at": m.created_at.isoformat() if m.created_at else None}), 201


# ── Admin: verification + documentation trail ───────────────────────────
@community_bp.route("/admin/community/servers/<int:sid>/verify", methods=["POST"])
@token_required
@require_role("admin_platform")
def verify_server(sid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    body = request.get_json(silent=True) or {}
    server.is_verified = bool(body.get("verified", True))
    db.session.commit()
    docs_service.write_event(
        "server_verified",
        {"actor_id": g.user.id, "target": sid, "name": server.name, "verified": server.is_verified},
        actor_id=g.user.id,
    )
    return jsonify(ok=True, verified=server.is_verified)


@community_bp.route("/admin/community/events", methods=["GET"])
@token_required
@require_role("admin_platform")
def admin_events():
    days = request.args.get("days", default=7, type=int)
    events = docs_service.list_events(max(1, min(days, 30)))
    csv_path, _ = docs_service.daily_summary()
    return jsonify(
        events=events[-300:],
        event_count=len(events),
        docs_folder="docs/community/",
        today_csv=csv_path,
    )


@community_bp.route("/admin/community/events/download", methods=["GET"])
@token_required
@require_role("admin_platform")
def admin_events_download():
    csv_path, _ = docs_service.daily_summary()
    return send_file(csv_path, as_attachment=True,
                     download_name="community_report.csv", mimetype="text/csv")


# ══════════════════════════════════════════════════════════════════════════
# NEW ROUTES
# ══════════════════════════════════════════════════════════════════════════


# ── Message Reactions ──────────────────────────────────────────────────
@community_bp.route("/api/community/messages/<int:mid>/reactions", methods=["POST"])
@token_required
def add_reaction(mid):
    message = Message.query.get(mid)
    if message is None or message.deleted_at:
        return jsonify(error="Message not found"), 404
    member = cc.member_of(message.server_id)
    if member is None or not cc.can(member, Perm.READ):
        return jsonify(error="You cannot react to this message."), 403
    try:
        data = ReactionAdd().load(request.get_json(silent=True) or {})
    except ValidationError as exc:
        return jsonify(error="Validation failed", details=exc.messages), 400

    emoji = data["emoji"]
    existing = MessageReaction.query.filter_by(
        message_id=mid, user_id=g.user.id, emoji=emoji
    ).first()
    if existing:
        return jsonify(error="You already reacted with this emoji."), 409

    reaction = MessageReaction(
        message_id=mid, user_id=g.user.id, emoji=emoji, server_id=message.server_id
    )
    db.session.add(reaction)
    db.session.commit()
    return jsonify(ok=True, emoji=emoji), 201


@community_bp.route("/api/community/messages/<int:mid>/reactions/<emoji>", methods=["DELETE"])
@token_required
def remove_reaction(mid, emoji):
    message = Message.query.get(mid)
    if message is None or message.deleted_at:
        return jsonify(error="Message not found"), 404
    member = cc.member_of(message.server_id)
    if member is None:
        return jsonify(error="You are not a member of this server."), 403
    reaction = MessageReaction.query.filter_by(
        message_id=mid, user_id=g.user.id, emoji=emoji
    ).first()
    if reaction is None:
        return jsonify(error="Reaction not found"), 404
    db.session.delete(reaction)
    db.session.commit()
    return jsonify(ok=True)


@community_bp.route("/api/community/messages/<int:mid>/reactions", methods=["GET"])
@token_required
def list_reactions(mid):
    message = Message.query.get(mid)
    if message is None or message.deleted_at:
        return jsonify(error="Message not found"), 404
    member = cc.member_of(message.server_id)
    if member is None or not cc.can(member, Perm.READ):
        return jsonify(error="You cannot view reactions."), 403
    reactions = MessageReaction.query.filter_by(message_id=mid).all()
    grouped = {}
    for r in reactions:
        grouped.setdefault(r.emoji, []).append(r.user_id)
    return jsonify(reactions=grouped)


# ── Threads ─────────────────────────────────────────────────────────────
@community_bp.route("/api/community/threads", methods=["POST"])
@token_required
def create_thread():
    try:
        data = ThreadCreate().load(request.get_json(silent=True) or {})
    except ValidationError as exc:
        return jsonify(error="Validation failed", details=exc.messages), 400

    channel = Channel.query.get(data["channel_id"])
    if channel is None:
        return jsonify(error="Channel not found"), 404
    member = cc.member_of(channel.server_id)
    if member is None or not cc.can(member, Perm.SEND):
        return jsonify(error="You cannot create threads in this channel."), 403

    thread = Thread(
        name=data["name"].strip(),
        channel_id=channel.id,
        server_id=channel.server_id,
        creator_id=g.user.id,
    )
    db.session.add(thread)
    db.session.commit()
    return jsonify(ok=True, thread=thread.to_dict()), 201


@community_bp.route("/api/community/servers/<int:sid>/threads", methods=["GET"])
@token_required
def list_threads(sid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    member = cc.member_of(sid)
    if member is None or not cc.can(member, Perm.READ):
        return jsonify(error="You cannot view threads."), 403

    threads = Thread.query.filter_by(server_id=sid, is_archived=False).order_by(
        Thread.last_message_at.desc().nullslast(), Thread.id.desc()
    ).limit(100).all()
    return jsonify(threads=[t.to_dict() for t in threads])


@community_bp.route("/api/community/threads/<int:tid>", methods=["GET"])
@token_required
def get_thread(tid):
    thread = Thread.query.get(tid)
    if thread is None:
        return jsonify(error="Thread not found"), 404
    member = cc.member_of(thread.server_id)
    if member is None or not cc.can(member, Perm.READ):
        return jsonify(error="You cannot view this thread."), 403
    return jsonify(thread=thread.to_dict())


@community_bp.route("/api/community/threads/<int:tid>/messages", methods=["POST"])
@token_required
def send_thread_message(tid):
    thread = Thread.query.get(tid)
    if thread is None:
        return jsonify(error="Thread not found"), 404
    member = cc.member_of(thread.server_id)
    if member is None or not cc.can(member, Perm.SEND):
        return jsonify(error="You cannot send messages in this thread."), 403
    if cc.is_muted(member):
        return jsonify(error="You are muted in this server."), 403

    try:
        data = MessageCreate().load(request.get_json(silent=True) or {})
    except ValidationError as exc:
        return jsonify(error="Validation failed", details=exc.messages), 400

    text = data["body"].strip()
    if not text:
        return jsonify(error="Message is empty."), 400

    blocked_scam, scam_hits = scam_scan(text)
    link_info = scan_links(text)
    if blocked_scam or link_info["status"] == "blocked":
        return jsonify(error="Message blocked by security filter."), 400

    message = Message(
        server_id=thread.server_id,
        channel_id=thread.channel_id,
        author_id=g.user.id,
        body=text,
        link_status=link_info["status"],
        kind="text",
    )
    db.session.add(message)
    db.session.flush()

    thread.message_count += 1
    thread.last_message_at = datetime.utcnow()
    db.session.commit()

    realtime.emit_channel_message(message.to_dict())
    return jsonify(ok=True, message=message.to_dict()), 201


@community_bp.route("/api/community/threads/<int:tid>/messages", methods=["GET"])
@token_required
def list_thread_messages(tid):
    thread = Thread.query.get(tid)
    if thread is None:
        return jsonify(error="Thread not found"), 404
    member = cc.member_of(thread.server_id)
    if member is None or not cc.can(member, Perm.READ):
        return jsonify(error="You cannot view this thread."), 403

    after = request.args.get("after", type=int, default=0)
    q = Message.query.filter(
        Message.channel_id == thread.channel_id,
        Message.deleted_at.is_(None),
        Message.created_at >= (thread.created_at or datetime.min),
    )
    if after:
        q = q.filter(Message.id > after)
    msgs = q.order_by(Message.id.asc()).limit(200).all()
    return jsonify(messages=[m.to_dict() for m in msgs])


@community_bp.route("/api/community/threads/<int:tid>", methods=["DELETE"])
@token_required
def delete_thread(tid):
    thread = Thread.query.get(tid)
    if thread is None:
        return jsonify(error="Thread not found"), 404
    member = cc.member_of(thread.server_id)
    is_creator = thread.creator_id == g.user.id
    can_manage = member and cc.can(member, Perm.MANAGE_MESSAGES)
    if not is_creator and not can_manage:
        return jsonify(error="You cannot delete this thread."), 403
    db.session.delete(thread)
    db.session.commit()
    return jsonify(ok=True)


# ── Channel Categories ──────────────────────────────────────────────────
@community_bp.route("/api/community/servers/<int:sid>/categories", methods=["POST"])
@token_required
def create_category(sid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    _, err, status = _require_perm(server, Perm.MANAGE_CHANNELS)
    if err:
        return err, status
    try:
        data = CategoryCreate().load(request.get_json(silent=True) or {})
    except ValidationError as exc:
        return jsonify(error="Validation failed", details=exc.messages), 400

    category = ChannelCategory(
        server_id=sid, name=data["name"].strip(), position=data["position"]
    )
    db.session.add(category)
    db.session.commit()
    return jsonify(ok=True, category=category.to_dict()), 201


@community_bp.route("/api/community/categories/<int:cat_id>", methods=["PATCH"])
@token_required
def edit_category(cat_id):
    category = ChannelCategory.query.get(cat_id)
    if category is None:
        return jsonify(error="Category not found"), 404
    _, err, status = _require_perm(_server_or_404(category.server_id), Perm.MANAGE_CHANNELS)
    if err:
        return err, status
    body = request.get_json(silent=True) or {}
    if "name" in body:
        category.name = body["name"].strip()
    if "position" in body:
        category.position = body["position"]
    db.session.commit()
    return jsonify(ok=True, category=category.to_dict())


@community_bp.route("/api/community/categories/<int:cat_id>", methods=["DELETE"])
@token_required
def delete_category(cat_id):
    category = ChannelCategory.query.get(cat_id)
    if category is None:
        return jsonify(error="Category not found"), 404
    _, err, status = _require_perm(_server_or_404(category.server_id), Perm.MANAGE_CHANNELS)
    if err:
        return err, status
    Channel.query.filter_by(category_id=cat_id).update({"category_id": None})
    db.session.delete(category)
    db.session.commit()
    return jsonify(ok=True)


@community_bp.route("/api/community/channels/<int:cid>/category", methods=["PATCH"])
@token_required
def move_channel_to_category(cid):
    channel = Channel.query.get(cid)
    if channel is None:
        return jsonify(error="Channel not found"), 404
    _, err, status = _require_perm(_server_or_404(channel.server_id), Perm.MANAGE_CHANNELS)
    if err:
        return err, status
    body = request.get_json(silent=True) or {}
    cat_id = body.get("category_id")
    if cat_id is not None:
        cat = ChannelCategory.query.get(cat_id)
        if cat is None or cat.server_id != channel.server_id:
            return jsonify(error="Category not found in this server."), 400
    channel.category_id = cat_id
    db.session.commit()
    return jsonify(ok=True, channel=channel.to_dict())


# ── Pin Messages ────────────────────────────────────────────────────────
@community_bp.route("/api/community/channels/<int:cid>/pins/<int:mid>", methods=["POST"])
@token_required
def pin_message(cid, mid):
    channel = Channel.query.get(cid)
    if channel is None:
        return jsonify(error="Channel not found"), 404
    _, err, status = _require_perm(_server_or_404(channel.server_id), Perm.MANAGE_MESSAGES)
    if err:
        return err, status
    message = Message.query.get(mid)
    if message is None or message.deleted_at:
        return jsonify(error="Message not found"), 404
    if message.channel_id != cid:
        return jsonify(error="Message does not belong to this channel."), 400

    existing = PinnedMessage.query.filter_by(channel_id=cid, message_id=mid).first()
    if existing:
        return jsonify(error="Message is already pinned."), 409

    pin = PinnedMessage(channel_id=cid, message_id=mid, pinned_by=g.user.id)
    db.session.add(pin)
    db.session.commit()
    return jsonify(ok=True), 201


@community_bp.route("/api/community/channels/<int:cid>/pins/<int:mid>", methods=["DELETE"])
@token_required
def unpin_message(cid, mid):
    channel = Channel.query.get(cid)
    if channel is None:
        return jsonify(error="Channel not found"), 404
    _, err, status = _require_perm(_server_or_404(channel.server_id), Perm.MANAGE_MESSAGES)
    if err:
        return err, status
    pin = PinnedMessage.query.filter_by(channel_id=cid, message_id=mid).first()
    if pin is None:
        return jsonify(error="Pin not found"), 404
    db.session.delete(pin)
    db.session.commit()
    return jsonify(ok=True)


@community_bp.route("/api/community/channels/<int:cid>/pins", methods=["GET"])
@token_required
def list_pins(cid):
    channel = Channel.query.get(cid)
    if channel is None:
        return jsonify(error="Channel not found"), 404
    member = cc.member_of(channel.server_id)
    if member is None or not cc.can(member, Perm.READ):
        return jsonify(error="You cannot view pins."), 403

    pins = PinnedMessage.query.filter_by(channel_id=cid).order_by(PinnedMessage.id.desc()).limit(50).all()
    out = []
    for p in pins:
        msg = Message.query.get(p.message_id)
        if msg and not msg.deleted_at:
            out.append({"pin": p.to_dict(), "message": msg.to_dict()})
    return jsonify(pins=out)


# ── Custom Emoji ────────────────────────────────────────────────────────
@community_bp.route("/api/community/servers/<int:sid>/emoji", methods=["POST"])
@token_required
def create_emoji(sid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    _, err, status = _require_perm(server, Perm.MANAGE_SERVER)
    if err:
        return err, status
    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "").strip()
    url = (body.get("url") or "").strip()
    if not name or not url:
        return jsonify(error="name and url are required."), 400
    emoji = CustomEmoji(server_id=sid, name=name, url=url, creator_id=g.user.id)
    db.session.add(emoji)
    db.session.commit()
    return jsonify(ok=True, emoji=emoji.to_dict()), 201


@community_bp.route("/api/community/servers/<int:sid>/emoji", methods=["GET"])
@token_required
def list_emoji(sid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    member = cc.member_of(sid)
    if member is None or not cc.can(member, Perm.READ):
        return jsonify(error="You cannot view emoji."), 403
    emoji = CustomEmoji.query.filter_by(server_id=sid).order_by(CustomEmoji.name).all()
    return jsonify(emoji=[e.to_dict() for e in emoji])


@community_bp.route("/api/community/emoji/<int:eid>", methods=["DELETE"])
@token_required
def delete_emoji(eid):
    emoji = CustomEmoji.query.get(eid)
    if emoji is None:
        return jsonify(error="Emoji not found"), 404
    member = cc.member_of(emoji.server_id)
    is_creator = emoji.creator_id == g.user.id
    can_manage = member and cc.can(member, Perm.MANAGE_SERVER)
    if not is_creator and not can_manage:
        return jsonify(error="You cannot delete this emoji."), 403
    db.session.delete(emoji)
    db.session.commit()
    return jsonify(ok=True)


# ── Channel Permission Overrides ────────────────────────────────────────
@community_bp.route("/api/community/channels/<int:cid>/overrides", methods=["POST"])
@token_required
def set_channel_override(cid):
    channel = Channel.query.get(cid)
    if channel is None:
        return jsonify(error="Channel not found"), 404
    _, err, status = _require_perm(_server_or_404(channel.server_id), Perm.MANAGE_CHANNELS)
    if err:
        return err, status
    body = request.get_json(silent=True) or {}
    role_id = body.get("role_id")
    user_id = body.get("user_id")
    if not role_id and not user_id:
        return jsonify(error="Provide role_id or user_id."), 400

    query = ChannelPermissionOverride.query.filter_by(channel_id=cid)
    if role_id:
        query = query.filter_by(role_id=role_id)
    else:
        query = query.filter_by(user_id=user_id)
    existing = query.first()

    if existing:
        existing.allow = body.get("allow", existing.allow or 0)
        existing.deny = body.get("deny", existing.deny or 0)
        db.session.commit()
        return jsonify(ok=True, override=existing.to_dict())

    override = ChannelPermissionOverride(
        channel_id=cid,
        role_id=role_id,
        user_id=user_id,
        allow=body.get("allow", 0),
        deny=body.get("deny", 0),
    )
    db.session.add(override)
    db.session.commit()
    return jsonify(ok=True, override=override.to_dict()), 201


@community_bp.route("/api/community/channels/<int:cid>/overrides", methods=["GET"])
@token_required
def list_channel_overrides(cid):
    channel = Channel.query.get(cid)
    if channel is None:
        return jsonify(error="Channel not found"), 404
    member = cc.member_of(channel.server_id)
    if member is None or not cc.can(member, Perm.MANAGE_CHANNELS):
        return jsonify(error="You cannot view overrides."), 403
    overrides = ChannelPermissionOverride.query.filter_by(channel_id=cid).all()
    return jsonify(overrides=[o.to_dict() for o in overrides])


@community_bp.route("/api/community/channels/<int:cid>/overrides/<int:oid>", methods=["DELETE"])
@token_required
def delete_channel_override(cid, oid):
    channel = Channel.query.get(cid)
    if channel is None:
        return jsonify(error="Channel not found"), 404
    _, err, status = _require_perm(_server_or_404(channel.server_id), Perm.MANAGE_CHANNELS)
    if err:
        return err, status
    override = ChannelPermissionOverride.query.filter_by(id=oid, channel_id=cid).first()
    if override is None:
        return jsonify(error="Override not found"), 404
    db.session.delete(override)
    db.session.commit()
    return jsonify(ok=True)


# ── User Status ─────────────────────────────────────────────────────────
@community_bp.route("/api/community/status", methods=["PATCH"])
@token_required
def set_own_status():
    body = request.get_json(silent=True) or {}
    status_val = body.get("status", "online")
    custom_status = body.get("custom_status", "")
    if status_val not in ("online", "idle", "dnd", "invisible"):
        return jsonify(error="Invalid status."), 400

    user_status = UserStatus.query.filter_by(user_id=g.user.id).first()
    if user_status:
        user_status.status = status_val
        user_status.custom_status = custom_status[:120] if custom_status else ""
        user_status.updated_at = datetime.utcnow()
    else:
        user_status = UserStatus(
            user_id=g.user.id, status=status_val,
            custom_status=custom_status[:120] if custom_status else "",
        )
        db.session.add(user_status)
    db.session.commit()
    return jsonify(ok=True, user_status=user_status.to_dict())


@community_bp.route("/api/community/users/<int:uid>/status", methods=["GET"])
@token_required
def get_user_status(uid):
    user_status = UserStatus.query.filter_by(user_id=uid).first()
    if user_status is None:
        return jsonify(status="online", custom_status="")
    return jsonify(status=user_status.status, custom_status=user_status.custom_status)


# ── Scheduled Events ────────────────────────────────────────────────────
@community_bp.route("/api/community/servers/<int:sid>/events", methods=["POST"])
@token_required
def create_event(sid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    _, err, status = _require_perm(server, Perm.MANAGE_SERVER)
    if err:
        return err, status
    try:
        data = EventCreate().load(request.get_json(silent=True) or {})
    except ValidationError as exc:
        return jsonify(error="Validation failed", details=exc.messages), 400

    start_at = datetime.fromisoformat(data["start_at"].replace("Z", "+00:00").replace("+00:00", ""))
    end_at = None
    if data.get("end_at"):
        end_at = datetime.fromisoformat(data["end_at"].replace("Z", "+00:00").replace("+00:00", ""))

    event = ScheduledEvent(
        server_id=sid,
        name=data["name"].strip(),
        description=data.get("description", ""),
        channel_id=data.get("channel_id"),
        creator_id=g.user.id,
        start_at=start_at,
        end_at=end_at,
        location=data.get("location", ""),
    )
    db.session.add(event)
    db.session.commit()
    return jsonify(ok=True, event=event.to_dict()), 201


@community_bp.route("/api/community/servers/<int:sid>/events", methods=["GET"])
@token_required
def list_events(sid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    member = cc.member_of(sid)
    if member is None or not cc.can(member, Perm.READ):
        return jsonify(error="You cannot view events."), 403
    events = ScheduledEvent.query.filter_by(server_id=sid).order_by(ScheduledEvent.start_at).all()
    return jsonify(events=[e.to_dict() for e in events])


@community_bp.route("/api/community/events/<int:eid>", methods=["PATCH"])
@token_required
def edit_event(eid):
    event = ScheduledEvent.query.get(eid)
    if event is None:
        return jsonify(error="Event not found"), 404
    _, err, status = _require_perm(_server_or_404(event.server_id), Perm.MANAGE_SERVER)
    if err:
        return err, status
    body = request.get_json(silent=True) or {}
    for key in ("name", "description", "location"):
        if key in body:
            setattr(event, key, body[key])
    if "channel_id" in body:
        event.channel_id = body["channel_id"]
    if "start_at" in body:
        event.start_at = datetime.fromisoformat(body["start_at"].replace("Z", "+00:00").replace("+00:00", ""))
    if "end_at" in body:
        if body["end_at"]:
            event.end_at = datetime.fromisoformat(body["end_at"].replace("Z", "+00:00").replace("+00:00", ""))
        else:
            event.end_at = None
    db.session.commit()
    return jsonify(ok=True, event=event.to_dict())


@community_bp.route("/api/community/events/<int:eid>", methods=["DELETE"])
@token_required
def cancel_event(eid):
    event = ScheduledEvent.query.get(eid)
    if event is None:
        return jsonify(error="Event not found"), 404
    _, err, status = _require_perm(_server_or_404(event.server_id), Perm.MANAGE_SERVER)
    if err:
        return err, status
    event.status = "cancelled"
    db.session.commit()
    return jsonify(ok=True)


@community_bp.route("/api/community/events/<int:eid>/rsvp", methods=["POST"])
@token_required
def rsvp_event(eid):
    event = ScheduledEvent.query.get(eid)
    if event is None:
        return jsonify(error="Event not found"), 404
    member = cc.member_of(event.server_id)
    if member is None:
        return jsonify(error="You are not a member of this server."), 403

    attending = _rsvps.setdefault(eid, [])
    if g.user.id in attending:
        return jsonify(error="You already RSVPed."), 409
    attending.append(g.user.id)
    return jsonify(ok=True, count=len(attending))


@community_bp.route("/api/community/events/<int:eid>/rsvp", methods=["GET"])
@token_required
def list_rsvps(eid):
    event = ScheduledEvent.query.get(eid)
    if event is None:
        return jsonify(error="Event not found"), 404
    member = cc.member_of(event.server_id)
    if member is None:
        return jsonify(error="You are not a member of this server."), 403
    user_ids = _rsvps.get(eid, [])
    users = User.query.filter(User.id.in_(user_ids)).all() if user_ids else []
    return jsonify(
        rsvps=[{"user_id": u.id, "username": u.name} for u in users],
        count=len(user_ids),
    )


# ── Auto-Moderation ─────────────────────────────────────────────────────
@community_bp.route("/api/community/servers/<int:sid>/automod", methods=["POST"])
@token_required
def create_automod_rule(sid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    _, err, status = _require_perm(server, Perm.ADMIN)
    if err:
        return err, status
    try:
        data = AutoModCreate().load(request.get_json(silent=True) or {})
    except ValidationError as exc:
        return jsonify(error="Validation failed", details=exc.messages), 400

    rule = AutoModRule(
        server_id=sid,
        name=data["name"].strip(),
        trigger_type=data["trigger_type"],
        trigger_value=data.get("trigger_value", ""),
        action_type=data["action_type"],
        action_duration_minutes=data.get("action_duration_minutes", 0),
        creator_id=g.user.id,
    )
    db.session.add(rule)
    db.session.commit()
    return jsonify(ok=True, rule=rule.to_dict()), 201


@community_bp.route("/api/community/servers/<int:sid>/automod", methods=["GET"])
@token_required
def list_automod_rules(sid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    member = cc.member_of(sid)
    if member is None or not cc.can(member, Perm.VIEW_AUDIT):
        return jsonify(error="You cannot view automod rules."), 403
    rules = AutoModRule.query.filter_by(server_id=sid).all()
    return jsonify(rules=[r.to_dict() for r in rules])


@community_bp.route("/api/community/automod/<int:rid>", methods=["PATCH"])
@token_required
def edit_automod_rule(rid):
    rule = AutoModRule.query.get(rid)
    if rule is None:
        return jsonify(error="Rule not found"), 404
    _, err, status = _require_perm(_server_or_404(rule.server_id), Perm.ADMIN)
    if err:
        return err, status
    body = request.get_json(silent=True) or {}
    for key in ("name", "trigger_type", "trigger_value", "action_type", "action_duration_minutes", "enabled"):
        if key in body:
            setattr(rule, key, body[key])
    db.session.commit()
    return jsonify(ok=True, rule=rule.to_dict())


@community_bp.route("/api/community/automod/<int:rid>", methods=["DELETE"])
@token_required
def delete_automod_rule(rid):
    rule = AutoModRule.query.get(rid)
    if rule is None:
        return jsonify(error="Rule not found"), 404
    _, err, status = _require_perm(_server_or_404(rule.server_id), Perm.ADMIN)
    if err:
        return err, status
    db.session.delete(rule)
    db.session.commit()
    return jsonify(ok=True)


# ── Webhooks ────────────────────────────────────────────────────────────
@community_bp.route("/api/community/servers/<int:sid>/webhooks", methods=["POST"])
@token_required
def create_webhook(sid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    _, err, status = _require_perm(server, Perm.MANAGE_SERVER)
    if err:
        return err, status
    try:
        data = WebhookCreate().load(request.get_json(silent=True) or {})
    except ValidationError as exc:
        return jsonify(error="Validation failed", details=exc.messages), 400

    channel = Channel.query.filter_by(id=data["channel_id"], server_id=sid).first()
    if channel is None:
        return jsonify(error="Channel not found in this server."), 400

    token = secrets.token_urlsafe(32)
    webhook = Webhook(
        server_id=sid,
        channel_id=data["channel_id"],
        name=data["name"].strip(),
        token=token,
        creator_id=g.user.id,
    )
    db.session.add(webhook)
    db.session.commit()
    return jsonify(ok=True, webhook=webhook.to_dict()), 201


@community_bp.route("/api/community/servers/<int:sid>/webhooks", methods=["GET"])
@token_required
def list_webhooks(sid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    _, err, status = _require_perm(server, Perm.MANAGE_SERVER)
    if err:
        return err, status
    webhooks = Webhook.query.filter_by(server_id=sid).all()
    return jsonify(webhooks=[w.to_dict() for w in webhooks])


@community_bp.route("/api/community/webhooks/<int:wid>", methods=["DELETE"])
@token_required
def delete_webhook(wid):
    webhook = Webhook.query.get(wid)
    if webhook is None:
        return jsonify(error="Webhook not found"), 404
    _, err, status = _require_perm(_server_or_404(webhook.server_id), Perm.MANAGE_SERVER)
    if err:
        return err, status
    db.session.delete(webhook)
    db.session.commit()
    return jsonify(ok=True)


@community_bp.route("/api/community/webhooks/<token>/post", methods=["POST"])
def webhook_post(token):
    """Webhook ingest endpoint — NO auth required, uses the webhook token."""
    webhook = Webhook.query.filter_by(token=token).first()
    if webhook is None:
        return jsonify(error="Invalid webhook token."), 401

    body = request.get_json(silent=True) or {}
    text = (body.get("content") or body.get("body") or "").strip()
    if not text:
        return jsonify(error="Content is required."), 400

    blocked_scam, _ = scam_scan(text)
    link_info = scan_links(text)
    if blocked_scam or link_info["status"] == "blocked":
        return jsonify(error="Content blocked by security filter."), 400

    message = Message(
        server_id=webhook.server_id,
        channel_id=webhook.channel_id,
        author_id=webhook.creator_id,
        body=text,
        link_status=link_info["status"],
        kind="text",
    )
    db.session.add(message)
    db.session.commit()

    realtime.emit_channel_message(message.to_dict())
    return jsonify(ok=True, message=message.to_dict()), 201


# ── Stickers ────────────────────────────────────────────────────────────
@community_bp.route("/api/community/servers/<int:sid>/stickers", methods=["POST"])
@token_required
def create_sticker(sid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    _, err, status = _require_perm(server, Perm.MANAGE_SERVER)
    if err:
        return err, status
    try:
        data = StickerCreate().load(request.get_json(silent=True) or {})
    except ValidationError as exc:
        return jsonify(error="Validation failed", details=exc.messages), 400

    sticker = Sticker(
        server_id=sid,
        name=data["name"].strip(),
        url=data["url"],
        tags=data.get("tags", ""),
        creator_id=g.user.id,
    )
    db.session.add(sticker)
    db.session.commit()
    return jsonify(ok=True, sticker=sticker.to_dict()), 201


@community_bp.route("/api/community/servers/<int:sid>/stickers", methods=["GET"])
@token_required
def list_stickers(sid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    member = cc.member_of(sid)
    if member is None or not cc.can(member, Perm.READ):
        return jsonify(error="You cannot view stickers."), 403
    stickers = Sticker.query.filter_by(server_id=sid).order_by(Sticker.name).all()
    return jsonify(stickers=[s.to_dict() for s in stickers])


@community_bp.route("/api/community/stickers/<int:stid>", methods=["DELETE"])
@token_required
def delete_sticker(stid):
    sticker = Sticker.query.get(stid)
    if sticker is None:
        return jsonify(error="Sticker not found"), 404
    _, err, status = _require_perm(_server_or_404(sticker.server_id), Perm.MANAGE_SERVER)
    if err:
        return err, status
    db.session.delete(sticker)
    db.session.commit()
    return jsonify(ok=True)


# ── Server Templates ────────────────────────────────────────────────────
@community_bp.route("/api/community/servers/<int:sid>/templates", methods=["POST"])
@token_required
def create_template(sid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    _, err, status = _require_perm(server, Perm.MANAGE_SERVER)
    if err:
        return err, status
    try:
        data = TemplateCreate().load(request.get_json(silent=True) or {})
    except ValidationError as exc:
        return jsonify(error="Validation failed", details=exc.messages), 400

    channels = Channel.query.filter_by(server_id=sid).order_by(Channel.position).all()
    roles = ServerRole.query.filter_by(server_id=sid).order_by(ServerRole.rank.desc()).all()
    template_data = json.dumps({
        "channels": [{"name": c.name, "kind": c.kind, "topic": c.topic} for c in channels],
        "roles": [{"name": r.name, "permissions": r.permissions, "color": r.color} for r in roles],
    })

    template = ServerTemplate(
        server_id=sid,
        name=data["name"].strip(),
        description=data.get("description", ""),
        template_data=template_data,
        creator_id=g.user.id,
    )
    db.session.add(template)
    db.session.commit()
    return jsonify(ok=True, template=template.to_dict()), 201


@community_bp.route("/api/community/servers/<int:sid>/templates", methods=["GET"])
@token_required
def list_templates(sid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    member = cc.member_of(sid)
    if member is None:
        return jsonify(error="You are not a member of this server."), 403
    templates = ServerTemplate.query.filter_by(server_id=sid).order_by(ServerTemplate.id.desc()).all()
    return jsonify(templates=[t.to_dict() for t in templates])


@community_bp.route("/api/community/templates/<int:tid>/use", methods=["POST"])
@token_required
def use_template(tid):
    template = ServerTemplate.query.get(tid)
    if template is None:
        return jsonify(error="Template not found"), 404

    body = request.get_json(silent=True) or {}
    name = (body.get("name") or template.name).strip()[:80]
    slug = name.lower().replace(" ", "-")[:80]
    base_slug = slug
    n = 1
    while CommunityServer.query.filter_by(slug=slug).first():
        n += 1
        slug = f"{base_slug}-{n}"

    server = CommunityServer(
        name=name, slug=slug, description="",
        invite_code=secrets.token_urlsafe(8),
        owner_id=g.user.id, retention_days=0,
    )
    db.session.add(server)
    db.session.flush()

    everyone = ServerRole(
        server_id=server.id, name="@everyone", rank=0,
        permissions=Perm.DEFAULT_MEMBER, is_default=True,
    )
    db.session.add(everyone)
    db.session.flush()

    template_data = json.loads(template.template_data) if template.template_data else {}
    for ch_data in template_data.get("channels", []):
        db.session.add(Channel(
            server_id=server.id, name=ch_data["name"], kind=ch_data.get("kind", "text"),
            topic=ch_data.get("topic", ""), created_by=g.user.id,
        ))
    for role_data in template_data.get("roles", []):
        if role_data["name"] == "@everyone":
            continue
        db.session.add(ServerRole(
            server_id=server.id, name=role_data["name"],
            permissions=role_data.get("permissions", Perm.DEFAULT_MEMBER),
            color=role_data.get("color", "#99aab5"),
        ))

    db.session.add(ServerMember(server_id=server.id, user_id=g.user.id, role_id=everyone.id))
    template.use_count += 1
    db.session.commit()
    return jsonify(ok=True, server=server.to_dict(1)), 201


# ── Message Search ──────────────────────────────────────────────────────
@community_bp.route("/api/community/servers/<int:sid>/search", methods=["GET"])
@token_required
def search_messages(sid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    member = cc.member_of(sid)
    if member is None or not cc.can(member, Perm.READ):
        return jsonify(error="You cannot search messages."), 403

    query = request.args.get("q", "").strip()
    if not query:
        return jsonify(error="Query parameter 'q' is required."), 400
    if len(query) > 200:
        return jsonify(error="Query too long."), 400

    limit = min(request.args.get("limit", type=int, default=50), 100)
    channel_id = request.args.get("channel_id", type=int)

    q = Message.query.filter(
        Message.server_id == sid,
        Message.deleted_at.is_(None),
        Message.flagged.is_(False),
        Message.body.ilike(f"%{query}%"),
    )
    if channel_id:
        q = q.filter(Message.channel_id == channel_id)
    msgs = q.order_by(Message.id.desc()).limit(limit).all()
    return jsonify(messages=[m.to_dict() for m in msgs])


# ── Message Forwarding ─────────────────────────────────────────────────
@community_bp.route("/api/community/messages/forward", methods=["POST"])
@token_required
def forward_message():
    try:
        data = MessageForward().load(request.get_json(silent=True) or {})
    except ValidationError as exc:
        return jsonify(error="Validation failed", details=exc.messages), 400

    original = Message.query.get(data["message_id"])
    if original is None or original.deleted_at:
        return jsonify(error="Source message not found."), 404

    src_member = cc.member_of(original.server_id)
    if src_member is None or not cc.can(src_member, Perm.READ):
        return jsonify(error="You cannot read the source message."), 403

    dest_channel = Channel.query.get(data["channel_id"])
    if dest_channel is None:
        return jsonify(error="Destination channel not found."), 404

    dest_member = cc.member_of(dest_channel.server_id)
    if dest_member is None or not cc.can(dest_member, Perm.SEND):
        return jsonify(error="You cannot send in the destination channel."), 403

    forwarding_author = User.query.get(original.author_id)
    fwd_text = (
        f"**Forwarded message** from @{forwarding_author.name if forwarding_author else 'unknown'}:\n"
        f"{original.body}"
    )

    new_msg = Message(
        server_id=dest_channel.server_id,
        channel_id=dest_channel.id,
        author_id=g.user.id,
        body=fwd_text,
        link_status="none",
    )
    db.session.add(new_msg)
    db.session.commit()
    realtime.emit_channel_message(new_msg.to_dict())
    return jsonify(ok=True, message=new_msg.to_dict()), 201


# ── Server Discovery ───────────────────────────────────────────────────
@community_bp.route("/api/community/discover", methods=["GET"])
@token_required
def discover_servers():
    page = request.args.get("page", type=int, default=1)
    per_page = min(request.args.get("per_page", type=int, default=20), 50)
    offset = (page - 1) * per_page

    # Servers are discoverable if they have a non-empty description.
    q = CommunityServer.query.filter(
        CommunityServer.description.isnot(None),
        CommunityServer.description != "",
    ).order_by(CommunityServer.name)

    total = q.count()
    servers = q.offset(offset).limit(per_page).all()
    return jsonify(
        servers=[s.to_dict(_member_count(s.id)) for s in servers],
        page=page,
        per_page=per_page,
        total=total,
    )


@community_bp.route("/api/community/servers/<int:sid>/discover", methods=["POST"])
@token_required
def toggle_discoverability(sid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    _, err, status = _require_perm(server, Perm.MANAGE_SERVER)
    if err:
        return err, status

    body = request.get_json(silent=True) or {}
    discoverable = body.get("discoverable")
    if discoverable is None:
        # Toggle: if description is set, clear it (hide); otherwise, set a placeholder.
        if server.description:
            server.description = ""
        else:
            server.description = "A community server on Insyrium."
    else:
        if discoverable and not server.description:
            server.description = "A community server on Insyrium."
        elif not discoverable:
            server.description = ""
    db.session.commit()
    return jsonify(ok=True, discoverable=bool(server.description))


# ══════════════════════════════════════════════════════════════════════════
# DISCORD FEATURE ROUTES
# ══════════════════════════════════════════════════════════════════════════


# ── Levenshtein Distance Helper ──────────────────────────────────────────
def _levenshtein(s1, s2):
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]


# ── Session Fingerprinting Hook (Security) ──────────────────────────────
@community_bp.before_request
def _session_fingerprint():
    if not getattr(g, "user", None):
        return None
    raw = f"{request.remote_addr}|{request.headers.get('User-Agent', '')}"
    fp_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    existing = SessionFingerprint.query.filter_by(user_id=g.user.id).first()
    is_new = False
    if existing:
        if existing.fingerprint_hash != fp_hash:
            is_new = True
            existing.fingerprint_hash = fp_hash
            existing.ip_address = request.remote_addr or ""
            existing.user_agent = request.headers.get("User-Agent", "")[:512]
            existing.last_seen_at = datetime.utcnow()
            db.session.commit()
    else:
        is_new = True
        fp = SessionFingerprint(
            user_id=g.user.id,
            fingerprint_hash=fp_hash,
            ip_address=request.remote_addr or "",
            user_agent=request.headers.get("User-Agent", "")[:512],
        )
        db.session.add(fp)
        db.session.commit()
    if is_new and request.method in ("POST", "DELETE", "PATCH"):
        log_audit(
            g.user.id,
            "new_session_fingerprint",
            metadata={
                "ip": request.remote_addr or "",
                "ua": request.headers.get("User-Agent", "")[:120],
                "method": request.method,
                "path": request.path,
            },
        )
    return None


# ── 1. Group DMs (Encrypted at Rest) ────────────────────────────────────
@community_bp.route("/api/community/group-dms", methods=["POST"])
@token_required
def create_group_dm():
    try:
        data = GroupDmCreate().load(request.get_json(silent=True) or {})
    except ValidationError as exc:
        return jsonify(error="Validation failed", details=exc.messages), 400

    user_ids = list(set(data["user_ids"] + [g.user.id]))
    if len(user_ids) < 2:
        return jsonify(error="At least 2 users are required."), 400

    thread = GroupDmThread(
        name=data.get("name", "Group Chat").strip(),
        creator_id=g.user.id,
    )
    db.session.add(thread)
    db.session.flush()

    for uid in user_ids:
        db.session.add(GroupDmMember(thread_id=thread.id, user_id=uid))
    db.session.commit()

    log_audit(g.user.id, "group_dm_created", target_id=thread.id,
              metadata={"name": thread.name, "member_count": len(user_ids)})
    return jsonify(ok=True, thread_id=thread.id), 201


@community_bp.route("/api/community/group-dms", methods=["GET"])
@token_required
def list_group_dms():
    memberships = GroupDmMember.query.filter_by(user_id=g.user.id).all()
    thread_ids = [m.thread_id for m in memberships]
    threads = GroupDmThread.query.filter(GroupDmThread.id.in_(thread_ids)).order_by(
        GroupDmThread.id.desc()
    ).all() if thread_ids else []
    out = []
    for t in threads:
        members = GroupDmMember.query.filter_by(thread_id=t.id).all()
        member_users = []
        for m in members:
            u = User.query.get(m.user_id)
            member_users.append({"user_id": m.user_id, "username": u.name if u else "unknown"})
        out.append({
            "id": t.id,
            "name": t.name,
            "creator_id": t.creator_id,
            "members": member_users,
            "created_at": t.created_at.isoformat() if t.created_at else None,
        })
    return jsonify(group_dms=out)


@community_bp.route("/api/community/group-dms/<int:tid>/messages", methods=["GET"])
@token_required
def group_dm_messages(tid):
    thread = GroupDmThread.query.get(tid)
    if thread is None:
        return jsonify(error="Group DM not found"), 404
    membership = GroupDmMember.query.filter_by(thread_id=tid, user_id=g.user.id).first()
    if membership is None:
        return jsonify(error="You are not a member of this group DM."), 403

    after = request.args.get("after", type=int, default=0)
    q = GroupDmMessage.query.filter_by(thread_id=tid)
    if after:
        q = q.filter(GroupDmMessage.id > after)
    msgs = q.order_by(GroupDmMessage.id.asc()).limit(200).all()
    out = []
    for m in msgs:
        try:
            body = _decrypt(m.ciphertext)
        except Exception:
            body = "[unreadable]"
        out.append({
            "id": m.id,
            "sender_id": m.sender_id,
            "body": body,
            "created_at": m.created_at.isoformat() if m.created_at else None,
        })
    return jsonify(messages=out)


@community_bp.route("/api/community/group-dms/<int:tid>/messages", methods=["POST"])
@token_required
def send_group_dm(tid):
    thread = GroupDmThread.query.get(tid)
    if thread is None:
        return jsonify(error="Group DM not found"), 404
    membership = GroupDmMember.query.filter_by(thread_id=tid, user_id=g.user.id).first()
    if membership is None:
        return jsonify(error="You are not a member of this group DM."), 403

    try:
        data = MessageCreate().load(request.get_json(silent=True) or {})
    except ValidationError as exc:
        return jsonify(error="Validation failed", details=exc.messages), 400

    text = data["body"].strip()
    blocked_scam, scam_hits = scam_scan(text)
    link_info = scan_links(text)
    if blocked_scam or link_info["status"] == "blocked":
        return jsonify(error="Message blocked by security filter."), 400

    m = GroupDmMessage(thread_id=tid, sender_id=g.user.id, ciphertext=_encrypt(text))
    db.session.add(m)
    db.session.commit()

    members = GroupDmMember.query.filter_by(thread_id=tid).all()
    for mem in members:
        if mem.user_id != g.user.id:
            cc.notify(mem.user_id, "dm", f"New message in {thread.name}", text[:120], "/community/group-dms")

    return jsonify(ok=True, message={
        "id": m.id, "sender_id": m.sender_id, "body": text,
        "created_at": m.created_at.isoformat() if m.created_at else None,
    }), 201


@community_bp.route("/api/community/group-dms/<int:tid>/members", methods=["POST"])
@token_required
def add_group_dm_member(tid):
    thread = GroupDmThread.query.get(tid)
    if thread is None:
        return jsonify(error="Group DM not found"), 404
    membership = GroupDmMember.query.filter_by(thread_id=tid, user_id=g.user.id).first()
    if membership is None:
        return jsonify(error="You are not a member of this group DM."), 403

    body = request.get_json(silent=True) or {}
    uid = body.get("user_id")
    if not uid:
        return jsonify(error="user_id is required."), 400

    existing = GroupDmMember.query.filter_by(thread_id=tid, user_id=uid).first()
    if existing:
        return jsonify(error="User is already a member."), 409

    db.session.add(GroupDmMember(thread_id=tid, user_id=uid))
    db.session.commit()
    return jsonify(ok=True), 201


@community_bp.route("/api/community/group-dms/<int:tid>/members/<int:uid>", methods=["DELETE"])
@token_required
def remove_group_dm_member(tid, uid):
    thread = GroupDmThread.query.get(tid)
    if thread is None:
        return jsonify(error="Group DM not found"), 404
    membership = GroupDmMember.query.filter_by(thread_id=tid, user_id=g.user.id).first()
    if membership is None:
        return jsonify(error="You are not a member of this group DM."), 403

    target = GroupDmMember.query.filter_by(thread_id=tid, user_id=uid).first()
    if target is None:
        return jsonify(error="Member not found"), 404

    if uid != g.user.id and thread.creator_id != g.user.id:
        return jsonify(error="Only the creator can remove other members."), 403

    db.session.delete(target)
    db.session.commit()
    return jsonify(ok=True)


@community_bp.route("/api/community/group-dms/<int:tid>/leave", methods=["DELETE"])
@token_required
def leave_group_dm(tid):
    thread = GroupDmThread.query.get(tid)
    if thread is None:
        return jsonify(error="Group DM not found"), 404
    membership = GroupDmMember.query.filter_by(thread_id=tid, user_id=g.user.id).first()
    if membership is None:
        return jsonify(error="You are not a member of this group DM."), 403

    db.session.delete(membership)
    db.session.commit()

    remaining = GroupDmMember.query.filter_by(thread_id=tid).count()
    if remaining == 0:
        GroupDmMessage.query.filter_by(thread_id=tid).delete()
        db.session.delete(thread)
        db.session.commit()

    return jsonify(ok=True)


# ── 2. Screen Sharing / Go Live ─────────────────────────────────────────
@community_bp.route("/api/community/channels/<int:cid>/screenshare", methods=["POST"])
@token_required
def start_screenshare(cid):
    channel = Channel.query.get(cid)
    if channel is None:
        return jsonify(error="Channel not found"), 404
    member = cc.member_of(channel.server_id)
    if member is None or not cc.can(member, Perm.VIEW):
        return jsonify(error="You cannot join this channel."), 403

    existing = ScreenShare.query.filter_by(
        channel_id=cid, user_id=g.user.id, is_active=True
    ).first()
    if existing:
        return jsonify(error="You are already screen sharing."), 409

    body = request.get_json(silent=True) or {}
    share = ScreenShare(
        channel_id=cid,
        server_id=channel.server_id,
        user_id=g.user.id,
        title=body.get("title", "")[:100],
        viewer_count=0,
        is_active=True,
    )
    db.session.add(share)
    db.session.commit()
    realtime.broadcast_voice(channel.server_id)
    return jsonify(ok=True, screenshare=share.to_dict()), 201


@community_bp.route("/api/community/channels/<int:cid>/screenshare", methods=["DELETE"])
@token_required
def stop_screenshare(cid):
    share = ScreenShare.query.filter_by(
        channel_id=cid, user_id=g.user.id, is_active=True
    ).first()
    if share is None:
        return jsonify(error="No active screenshare found."), 404
    share.is_active = False
    db.session.commit()
    return jsonify(ok=True)


@community_bp.route("/api/community/channels/<int:cid>/screenshare", methods=["GET"])
@token_required
def list_channel_screenshares(cid):
    channel = Channel.query.get(cid)
    if channel is None:
        return jsonify(error="Channel not found"), 404
    member = cc.member_of(channel.server_id)
    if member is None or not cc.can(member, Perm.READ):
        return jsonify(error="You cannot view this channel."), 403

    shares = ScreenShare.query.filter_by(channel_id=cid, is_active=True).all()
    out = []
    for s in shares:
        u = User.query.get(s.user_id)
        out.append({
            "id": s.id,
            "user_id": s.user_id,
            "username": u.name if u else "unknown",
            "title": s.title,
            "viewer_count": s.viewer_count,
            "created_at": s.created_at.isoformat() if s.created_at else None,
        })
    return jsonify(screenshares=out)


@community_bp.route("/api/community/screenshares/<int:sid>/viewers", methods=["POST"])
@token_required
def increment_screenshare_viewers(sid):
    share = ScreenShare.query.get(sid)
    if share is None or not share.is_active:
        return jsonify(error="Screenshare not found."), 404
    share.viewer_count += 1
    db.session.commit()
    return jsonify(ok=True, viewer_count=share.viewer_count)


@community_bp.route("/api/community/servers/<int:sid>/screenshares", methods=["GET"])
@token_required
def list_server_screenshares(sid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    member = cc.member_of(sid)
    if member is None or not cc.can(member, Perm.READ):
        return jsonify(error="You cannot view this server."), 403

    shares = ScreenShare.query.filter_by(server_id=sid, is_active=True).all()
    out = []
    for s in shares:
        u = User.query.get(s.user_id)
        ch = Channel.query.get(s.channel_id)
        out.append({
            "id": s.id,
            "user_id": s.user_id,
            "username": u.name if u else "unknown",
            "channel_id": s.channel_id,
            "channel_name": ch.name if ch else "unknown",
            "title": s.title,
            "viewer_count": s.viewer_count,
            "created_at": s.created_at.isoformat() if s.created_at else None,
        })
    return jsonify(screenshares=out)


# ── 3. Stage Channels ───────────────────────────────────────────────────
@community_bp.route("/api/community/servers/<int:sid>/stages", methods=["POST"])
@token_required
def create_stage(sid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    _, err, status = _require_perm(server, Perm.MANAGE_CHANNELS)
    if err:
        return err, status

    try:
        data = StageCreate().load(request.get_json(silent=True) or {})
    except ValidationError as exc:
        return jsonify(error="Validation failed", details=exc.messages), 400

    channel = Channel.query.filter_by(id=data["channel_id"], server_id=sid).first()
    if channel is None:
        return jsonify(error="Channel not found in this server."), 400

    stage = StageChannel(
        server_id=sid,
        channel_id=channel.id,
        topic=data.get("topic", ""),
        creator_id=g.user.id,
        is_live=False,
    )
    db.session.add(stage)
    db.session.commit()
    return jsonify(ok=True, stage=stage.to_dict()), 201


@community_bp.route("/api/community/servers/<int:sid>/stages", methods=["GET"])
@token_required
def list_stages(sid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    member = cc.member_of(sid)
    if member is None or not cc.can(member, Perm.READ):
        return jsonify(error="You cannot view this server."), 403

    stages = StageChannel.query.filter_by(server_id=sid).all()
    out = []
    for s in stages:
        out.append({
            "id": s.id,
            "channel_id": s.channel_id,
            "topic": s.topic,
            "is_live": s.is_live,
            "created_at": s.created_at.isoformat() if s.created_at else None,
        })
    return jsonify(stages=out)


@community_bp.route("/api/community/stages/<int:stid>/join", methods=["POST"])
@token_required
def join_stage(stid):
    stage = StageChannel.query.get(stid)
    if stage is None:
        return jsonify(error="Stage not found"), 404
    member = cc.member_of(stage.server_id)
    if member is None or not cc.can(member, Perm.VIEW):
        return jsonify(error="You cannot join this stage."), 403

    stage.is_live = True
    db.session.commit()
    realtime.voice_add(stage.channel_id, g.user.id)
    realtime.broadcast_voice(stage.server_id)
    return jsonify(ok=True, joined=True)


@community_bp.route("/api/community/stages/<int:stid>/leave", methods=["POST"])
@token_required
def leave_stage(stid):
    stage = StageChannel.query.get(stid)
    if stage is None:
        return jsonify(error="Stage not found"), 404
    realtime.voice_remove(stage.channel_id, g.user.id)
    realtime.broadcast_voice(stage.server_id)
    return jsonify(ok=True)


@community_bp.route("/api/community/stages/<int:stid>/speaker", methods=["POST"])
@token_required
def request_speaker(stid):
    stage = StageChannel.query.get(stid)
    if stage is None:
        return jsonify(error="Stage not found"), 404
    member = cc.member_of(stage.server_id)
    if member is None:
        return jsonify(error="You are not a member of this server."), 403

    _, err, status = _require_perm(_server_or_404(stage.server_id), Perm.MANAGE_CHANNELS)
    if err:
        _notify_moderators(stage.server_id, "Speaker request",
                           f"User {g.user.id} requested speaker in stage.")
        return jsonify(ok=True, requested=True)

    stage.is_live = True
    db.session.commit()
    return jsonify(ok=True, promoted=True)


@community_bp.route("/api/community/stages/<int:stid>", methods=["PATCH"])
@token_required
def edit_stage(stid):
    stage = StageChannel.query.get(stid)
    if stage is None:
        return jsonify(error="Stage not found"), 404
    _, err, status = _require_perm(_server_or_404(stage.server_id), Perm.MANAGE_CHANNELS)
    if err:
        return err, status

    body = request.get_json(silent=True) or {}
    if "topic" in body:
        stage.topic = body["topic"][:200]
    db.session.commit()
    return jsonify(ok=True, stage=stage.to_dict())


# ── 4. Nitro / Boosting ─────────────────────────────────────────────────
def _calc_boost_tier(boost_count):
    if boost_count >= 14:
        return 3
    if boost_count >= 7:
        return 2
    if boost_count >= 2:
        return 1
    return 0


def _boost_perks(tier):
    perks = {
        0: {},
        1: {
            "custom_emoji_everywhere": True,
            "upload_limit_mb": 100,
            "animated_server_icon": True,
        },
        2: {
            "custom_emoji_everywhere": True,
            "upload_limit_mb": 150,
            "animated_server_icon": True,
            "voice_bitrate": 128000,
            "server_banner": True,
        },
        3: {
            "custom_emoji_everywhere": True,
            "upload_limit_mb": 500,
            "animated_server_icon": True,
            "voice_bitrate": 384000,
            "server_banner": True,
            "vanity_url": True,
        },
    }
    return perks.get(tier, {})


@community_bp.route("/api/community/servers/<int:sid>/boost", methods=["POST"])
@token_required
def boost_server(sid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    member = cc.member_of(sid)
    if member is None:
        return jsonify(error="You are not a member of this server."), 403

    try:
        data = BoostTier().load(request.get_json(silent=True) or {})
    except ValidationError as exc:
        return jsonify(error="Validation failed", details=exc.messages), 400

    existing = ServerBoost.query.filter_by(server_id=sid, user_id=g.user.id, is_active=True).first()
    if existing:
        return jsonify(error="You are already boosting this server."), 409

    boost = ServerBoost(
        server_id=sid,
        user_id=g.user.id,
        tier=data["tier"],
        is_active=True,
    )
    db.session.add(boost)
    db.session.commit()

    boost_count = ServerBoost.query.filter_by(server_id=sid, is_active=True).count()
    new_tier = _calc_boost_tier(boost_count)

    log_audit(g.user.id, "server_boosted", target_id=sid,
              metadata={"tier": data["tier"], "server_tier": new_tier})
    return jsonify(ok=True, boost=boost.to_dict(), server_tier=new_tier), 201


@community_bp.route("/api/community/servers/<int:sid>/boosts", methods=["GET"])
@token_required
def list_boosts(sid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    member = cc.member_of(sid)
    if member is None or not cc.can(member, Perm.READ):
        return jsonify(error="You cannot view this server."), 403

    boosts = ServerBoost.query.filter_by(server_id=sid, is_active=True).all()
    boost_count = len(boosts)
    tier = _calc_boost_tier(boost_count)
    perks = _boost_perks(tier)

    out = []
    for b in boosts:
        u = User.query.get(b.user_id)
        out.append({
            "id": b.id,
            "user_id": b.user_id,
            "username": u.name if u else "unknown",
            "tier": b.tier,
            "created_at": b.created_at.isoformat() if b.created_at else None,
        })
    return jsonify(boosts=out, boost_count=boost_count, tier=tier, perks=perks)


@community_bp.route("/api/community/servers/<int:sid>/boost", methods=["DELETE"])
@token_required
def remove_boost(sid):
    boost = ServerBoost.query.filter_by(server_id=sid, user_id=g.user.id, is_active=True).first()
    if boost is None:
        return jsonify(error="You are not boosting this server."), 404
    boost.is_active = False
    db.session.commit()

    boost_count = ServerBoost.query.filter_by(server_id=sid, is_active=True).count()
    new_tier = _calc_boost_tier(boost_count)
    return jsonify(ok=True, server_tier=new_tier)


@community_bp.route("/api/community/servers/<int:sid>/boost-info", methods=["GET"])
@token_required
def boost_info(sid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    member = cc.member_of(sid)
    if member is None or not cc.can(member, Perm.READ):
        return jsonify(error="You cannot view this server."), 403

    boost_count = ServerBoost.query.filter_by(server_id=sid, is_active=True).count()
    current_tier = _calc_boost_tier(boost_count)
    perks = _boost_perks(current_tier)

    tier_thresholds = {0: 2, 1: 7, 2: 14, 3: None}
    next_needed = tier_thresholds.get(current_tier)
    next_tier = current_tier + 1 if current_tier < 3 else None

    return jsonify(
        boost_count=boost_count,
        current_tier=current_tier,
        perks=perks,
        next_tier=next_tier,
        boosts_until_next=(next_needed - boost_count) if next_needed else 0,
    )


# ── 5. Rich Presence ────────────────────────────────────────────────────
@community_bp.route("/api/community/status/presence", methods=["PATCH"])
@token_required
def update_presence():
    body = request.get_json(silent=True) or {}
    status_text = body.get("status_text", "")[:120]
    app_name = body.get("app_name", "")[:80]
    app_details = body.get("app_details", "")[:200]

    presence = RichPresence.query.filter_by(user_id=g.user.id).first()
    if presence:
        presence.status_text = status_text
        presence.app_name = app_name
        presence.app_details = app_details
        presence.updated_at = datetime.utcnow()
    else:
        presence = RichPresence(
            user_id=g.user.id,
            status_text=status_text,
            app_name=app_name,
            app_details=app_details,
        )
        db.session.add(presence)
    db.session.commit()
    return jsonify(ok=True, presence=presence.to_dict())


@community_bp.route("/api/community/users/<int:uid>/presence", methods=["GET"])
@token_required
def get_user_presence(uid):
    presence = RichPresence.query.filter_by(user_id=uid).first()
    if presence is None:
        return jsonify(presence=None)
    return jsonify(presence=presence.to_dict())


# ── 6. Forum Channels ───────────────────────────────────────────────────
@community_bp.route("/api/community/channels/<int:cid>/forum/posts", methods=["POST"])
@token_required
def create_forum_post(cid):
    channel = Channel.query.get(cid)
    if channel is None:
        return jsonify(error="Channel not found"), 404
    member = cc.member_of(channel.server_id)
    if member is None or not cc.can(member, Perm.SEND):
        return jsonify(error="You cannot create posts in this channel."), 403

    try:
        data = ForumPostCreate().load(request.get_json(silent=True) or {})
    except ValidationError as exc:
        return jsonify(error="Validation failed", details=exc.messages), 400

    post = ForumPost(
        channel_id=cid,
        server_id=channel.server_id,
        author_id=g.user.id,
        title=data["title"].strip(),
        body=data["body"].strip(),
        tags=data.get("tags", ""),
        is_pinned=False,
        is_locked=False,
    )
    db.session.add(post)
    db.session.commit()
    return jsonify(ok=True, post=post.to_dict()), 201


@community_bp.route("/api/community/channels/<int:cid>/forum/posts", methods=["GET"])
@token_required
def list_forum_posts(cid):
    channel = Channel.query.get(cid)
    if channel is None:
        return jsonify(error="Channel not found"), 404
    member = cc.member_of(channel.server_id)
    if member is None or not cc.can(member, Perm.READ):
        return jsonify(error="You cannot view this channel."), 403

    q = ForumPost.query.filter_by(channel_id=cid)
    tag_filter = request.args.get("tag")
    if tag_filter:
        q = q.filter(ForumPost.tags.ilike(f"%{tag_filter}%"))
    sort = request.args.get("sort", "newest")
    if sort == "popular":
        q = q.order_by(ForumPost.reply_count.desc(), ForumPost.id.desc())
    else:
        q = q.order_by(ForumPost.id.desc())
    posts = q.limit(100).all()
    return jsonify(posts=[p.to_dict() for p in posts])


@community_bp.route("/api/community/forum/posts/<int:pid>", methods=["GET"])
@token_required
def get_forum_post(pid):
    post = ForumPost.query.get(pid)
    if post is None:
        return jsonify(error="Post not found"), 404
    member = cc.member_of(post.server_id)
    if member is None or not cc.can(member, Perm.READ):
        return jsonify(error="You cannot view this post."), 403
    return jsonify(post=post.to_dict())


@community_bp.route("/api/community/forum/posts/<int:pid>/replies", methods=["POST"])
@token_required
def create_forum_reply(pid):
    post = ForumPost.query.get(pid)
    if post is None:
        return jsonify(error="Post not found"), 404
    if post.is_locked:
        return jsonify(error="This post is locked."), 403
    member = cc.member_of(post.server_id)
    if member is None or not cc.can(member, Perm.SEND):
        return jsonify(error="You cannot reply to this post."), 403

    try:
        data = ForumReplyCreate().load(request.get_json(silent=True) or {})
    except ValidationError as exc:
        return jsonify(error="Validation failed", details=exc.messages), 400

    reply = ForumReply(
        post_id=pid,
        author_id=g.user.id,
        body=data["body"].strip(),
    )
    db.session.add(reply)
    post.reply_count += 1
    db.session.commit()
    return jsonify(ok=True, reply=reply.to_dict()), 201


@community_bp.route("/api/community/forum/posts/<int:pid>/replies", methods=["GET"])
@token_required
def list_forum_replies(pid):
    post = ForumPost.query.get(pid)
    if post is None:
        return jsonify(error="Post not found"), 404
    member = cc.member_of(post.server_id)
    if member is None or not cc.can(member, Perm.READ):
        return jsonify(error="You cannot view replies."), 403

    replies = ForumReply.query.filter_by(post_id=pid).order_by(ForumReply.id.asc()).all()
    return jsonify(replies=[r.to_dict() for r in replies])


@community_bp.route("/api/community/forum/posts/<int:pid>", methods=["PATCH"])
@token_required
def edit_forum_post(pid):
    post = ForumPost.query.get(pid)
    if post is None:
        return jsonify(error="Post not found"), 404
    member = cc.member_of(post.server_id)
    can_manage = member and cc.can(member, Perm.MANAGE_MESSAGES)
    if not can_manage and post.author_id != g.user.id:
        return jsonify(error="You cannot edit this post."), 403

    body = request.get_json(silent=True) or {}
    if "title" in body and can_manage:
        post.title = body["title"][:100]
    if "body" in body:
        post.body = body["body"][:10000]
    if "tags" in body and can_manage:
        post.tags = body["tags"][:200]
    if "is_pinned" in body and can_manage:
        post.is_pinned = body["is_pinned"]
    if "is_locked" in body and can_manage:
        post.is_locked = body["is_locked"]
    db.session.commit()
    return jsonify(ok=True, post=post.to_dict())


@community_bp.route("/api/community/forum/posts/<int:pid>", methods=["DELETE"])
@token_required
def delete_forum_post(pid):
    post = ForumPost.query.get(pid)
    if post is None:
        return jsonify(error="Post not found"), 404
    member = cc.member_of(post.server_id)
    can_manage = member and cc.can(member, Perm.MANAGE_MESSAGES)
    if not can_manage and post.author_id != g.user.id:
        return jsonify(error="You cannot delete this post."), 403

    ForumReply.query.filter_by(post_id=pid).delete()
    db.session.delete(post)
    db.session.commit()
    return jsonify(ok=True)


# ── 7. Verification Levels ──────────────────────────────────────────────
@community_bp.route("/api/community/servers/<int:sid>/verification", methods=["PATCH"])
@token_required
def set_verification_level(sid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    _, err, status = _require_perm(server, Perm.MANAGE_SERVER)
    if err:
        return err, status

    body = request.get_json(silent=True) or {}
    level = body.get("level", 0)
    if level not in (0, 1, 2, 3, 4):
        return jsonify(error="Invalid verification level."), 400

    vl = VerificationLevel.query.filter_by(server_id=sid).first()
    if vl:
        vl.level = level
    else:
        vl = VerificationLevel(server_id=sid, level=level)
        db.session.add(vl)
    db.session.commit()
    log_audit(g.user.id, "verification_level_changed", target_id=sid,
              metadata={"level": level})
    return jsonify(ok=True, level=level)


@community_bp.route("/api/community/servers/<int:sid>/verification", methods=["GET"])
@token_required
def get_verification_level(sid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    vl = VerificationLevel.query.filter_by(server_id=sid).first()
    level = vl.level if vl else 0
    return jsonify(level=level)


# ── 8. Bot Integration System ───────────────────────────────────────────
@community_bp.route("/api/community/servers/<int:sid>/bots", methods=["POST"])
@token_required
def register_bot(sid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    _, err, status = _require_perm(server, Perm.MANAGE_BOTS)
    if err:
        return err, status

    try:
        data = BotCreate().load(request.get_json(silent=True) or {})
    except ValidationError as exc:
        return jsonify(error="Validation failed", details=exc.messages), 400

    token = secrets.token_urlsafe(48)
    bot = Bot(
        server_id=sid,
        name=data["name"].strip(),
        description=data.get("description", ""),
        token=token,
        creator_id=g.user.id,
        is_public=False,
    )
    db.session.add(bot)
    db.session.commit()
    log_audit(g.user.id, "bot_registered", target_id=bot.id,
              metadata={"name": bot.name, "server_id": sid})
    return jsonify(ok=True, bot=bot.to_dict()), 201


@community_bp.route("/api/community/servers/<int:sid>/bots", methods=["GET"])
@token_required
def list_bots(sid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    member = cc.member_of(sid)
    if member is None or not cc.can(member, Perm.READ):
        return jsonify(error="You cannot view bots."), 403

    bots = Bot.query.filter_by(server_id=sid).all()
    return jsonify(bots=[b.to_dict() for b in bots])


@community_bp.route("/api/community/bots/<int:bid>", methods=["DELETE"])
@token_required
def delete_bot(bid):
    bot = Bot.query.get(bid)
    if bot is None:
        return jsonify(error="Bot not found"), 404
    if bot.creator_id != g.user.id:
        _, err, status = _require_perm(_server_or_404(bot.server_id), Perm.MANAGE_BOTS)
        if err:
            return err, status
    db.session.delete(bot)
    db.session.commit()
    return jsonify(ok=True)


@community_bp.route("/api/community/bots/<int:bid>/regenerate-token", methods=["POST"])
@token_required
def regenerate_bot_token(bid):
    bot = Bot.query.get(bid)
    if bot is None:
        return jsonify(error="Bot not found"), 404
    if bot.creator_id != g.user.id:
        _, err, status = _require_perm(_server_or_404(bot.server_id), Perm.MANAGE_BOTS)
        if err:
            return err, status
    bot.token = secrets.token_urlsafe(48)
    db.session.commit()
    log_audit(g.user.id, "bot_token_regenerated", target_id=bid,
              metadata={"name": bot.name})
    return jsonify(ok=True, token=bot.token)


@community_bp.route("/api/community/bots/discover", methods=["GET"])
@token_required
def discover_bots():
    bots = Bot.query.filter_by(is_public=True).order_by(Bot.id.desc()).limit(50).all()
    return jsonify(bots=[b.to_dict() for b in bots])


@community_bp.route("/api/community/servers/<int:sid>/bots/<int:bid>/add", methods=["POST"])
@token_required
def add_bot_to_server(sid, bid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    bot = Bot.query.get(bid)
    if bot is None:
        return jsonify(error="Bot not found"), 404
    _, err, status = _require_perm(server, Perm.MANAGE_BOTS)
    if err:
        return err, status
    bot.server_id = sid
    db.session.commit()
    log_audit(g.user.id, "bot_added_to_server", target_id=bid,
              metadata={"server_id": sid, "name": bot.name})
    return jsonify(ok=True)


# ── 9. Onboarding Flow ──────────────────────────────────────────────────
@community_bp.route("/api/community/servers/<int:sid>/onboarding", methods=["POST"])
@token_required
def create_onboarding_step(sid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    _, err, status = _require_perm(server, Perm.MANAGE_SERVER)
    if err:
        return err, status

    try:
        data = OnboardingStepCreate().load(request.get_json(silent=True) or {})
    except ValidationError as exc:
        return jsonify(error="Validation failed", details=exc.messages), 400

    step = OnboardingStep(
        server_id=sid,
        title=data["title"].strip(),
        description=data.get("description", ""),
        required_role_id=data.get("required_role_id"),
        step_order=data.get("step_order", 0),
        creator_id=g.user.id,
    )
    db.session.add(step)
    db.session.commit()
    return jsonify(ok=True, step=step.to_dict()), 201


@community_bp.route("/api/community/servers/<int:sid>/onboarding", methods=["GET"])
@token_required
def list_onboarding_steps(sid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    member = cc.member_of(sid)
    if member is None:
        return jsonify(error="You are not a member."), 403

    steps = OnboardingStep.query.filter_by(server_id=sid).order_by(OnboardingStep.step_order).all()
    return jsonify(steps=[s.to_dict() for s in steps])


@community_bp.route("/api/community/onboarding/<int:sid>", methods=["PATCH"])
@token_required
def edit_onboarding_step(sid):
    step = OnboardingStep.query.get(sid)
    if step is None:
        return jsonify(error="Step not found"), 404
    _, err, status = _require_perm(_server_or_404(step.server_id), Perm.MANAGE_SERVER)
    if err:
        return err, status

    body = request.get_json(silent=True) or {}
    if "title" in body:
        step.title = body["title"][:80]
    if "description" in body:
        step.description = body["description"][:300]
    if "required_role_id" in body:
        step.required_role_id = body["required_role_id"]
    if "step_order" in body:
        step.step_order = body["step_order"]
    db.session.commit()
    return jsonify(ok=True, step=step.to_dict())


@community_bp.route("/api/community/onboarding/<int:sid>", methods=["DELETE"])
@token_required
def delete_onboarding_step(sid):
    step = OnboardingStep.query.get(sid)
    if step is None:
        return jsonify(error="Step not found"), 404
    _, err, status = _require_perm(_server_or_404(step.server_id), Perm.MANAGE_SERVER)
    if err:
        return err, status
    db.session.delete(step)
    db.session.commit()
    return jsonify(ok=True)


@community_bp.route("/api/community/servers/<int:sid>/onboarding/complete", methods=["POST"])
@token_required
def complete_onboarding(sid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    member = cc.member_of(sid)
    if member is None:
        return jsonify(error="You are not a member of this server."), 403

    steps = OnboardingStep.query.filter_by(server_id=sid).order_by(OnboardingStep.step_order).all()
    assigned_roles = []
    for step in steps:
        if step.required_role_id:
            role = ServerRole.query.get(step.required_role_id)
            if role and role.server_id == sid:
                member.role_id = role.id
                assigned_roles.append(role.name)

    member.onboarding_completed = True
    db.session.commit()
    return jsonify(ok=True, assigned_roles=assigned_roles)


# ── 10. Raid Protection ─────────────────────────────────────────────────
@community_bp.route("/api/community/servers/<int:sid>/raid-logs", methods=["GET"])
@token_required
def list_raid_logs(sid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    _, err, status = _require_perm(server, Perm.MODERATE)
    if err:
        return err, status

    logs = RaidLog.query.filter_by(server_id=sid).order_by(RaidLog.id.desc()).limit(50).all()
    return jsonify(raid_logs=[l.to_dict() for l in logs])


@community_bp.route("/api/community/servers/<int:sid>/raid-lock", methods=["POST"])
@token_required
def raid_lock(sid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    _, err, status = _require_perm(server, Perm.MANAGE_SERVER)
    if err:
        return err, status

    server.is_raid_locked = True
    db.session.commit()
    log_audit(g.user.id, "raid_lock_activated", target_id=sid)
    docs_service.write_event(
        "raid_lock", {"actor_id": g.user.id, "target": sid}, actor_id=g.user.id,
    )
    return jsonify(ok=True, raid_locked=True)


@community_bp.route("/api/community/servers/<int:sid>/raid-unlock", methods=["POST"])
@token_required
def raid_unlock(sid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    _, err, status = _require_perm(server, Perm.MANAGE_SERVER)
    if err:
        return err, status

    server.is_raid_locked = False
    db.session.commit()
    log_audit(g.user.id, "raid_lock_removed", target_id=sid)
    return jsonify(ok=True, raid_locked=False)


@community_bp.route("/api/community/servers/<int:sid>/raid-settings", methods=["PATCH"])
@token_required
def update_raid_settings(sid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    _, err, status = _require_perm(server, Perm.MANAGE_SERVER)
    if err:
        return err, status

    body = request.get_json(silent=True) or {}
    if "join_rate_limit" in body:
        server.join_rate_limit = body["join_rate_limit"]
    if "message_rate_limit" in body:
        server.message_rate_limit = body["message_rate_limit"]
    db.session.commit()
    return jsonify(ok=True)


# ── 11. Improved Notification Management ─────────────────────────────────
@community_bp.route("/api/community/notification-prefs", methods=["GET"])
@token_required
def get_notification_prefs():
    prefs = NotificationPreference.query.filter_by(user_id=g.user.id).all()
    return jsonify(preferences=[p.to_dict() for p in prefs])


@community_bp.route("/api/community/notification-prefs", methods=["PUT"])
@token_required
def update_notification_prefs():
    body = request.get_json(silent=True) or {}
    server_id = body.get("server_id")
    channel_id = body.get("channel_id")

    q = NotificationPreference.query.filter_by(user_id=g.user.id)
    if server_id:
        q = q.filter_by(server_id=server_id)
    if channel_id:
        q = q.filter_by(channel_id=channel_id)
    pref = q.first()

    if pref is None:
        pref = NotificationPreference(
            user_id=g.user.id,
            server_id=server_id,
            channel_id=channel_id,
        )
        db.session.add(pref)

    if "notify_mentions" in body:
        pref.notify_mentions = body["notify_mentions"]
    if "notify_replies" in body:
        pref.notify_replies = body["notify_replies"]
    if "notify_all_messages" in body:
        pref.notify_all_messages = body["notify_all_messages"]
    if "muted" in body:
        pref.muted = body["muted"]
    db.session.commit()
    return jsonify(ok=True, preference=pref.to_dict())


@community_bp.route("/api/community/channels/<int:cid>/mute", methods=["POST"])
@token_required
def mute_channel(cid):
    channel = Channel.query.get(cid)
    if channel is None:
        return jsonify(error="Channel not found"), 404
    member = cc.member_of(channel.server_id)
    if member is None:
        return jsonify(error="You are not a member."), 403

    body = request.get_json(silent=True) or {}
    until_hours = body.get("until_hours", 24)

    pref = NotificationPreference.query.filter_by(
        user_id=g.user.id, channel_id=cid
    ).first()
    if pref is None:
        pref = NotificationPreference(user_id=g.user.id, channel_id=cid)
        db.session.add(pref)
    pref.muted = True
    pref.muted_until = datetime.utcnow() + timedelta(hours=until_hours)
    db.session.commit()
    return jsonify(ok=True)


@community_bp.route("/api/community/channels/<int:cid>/mute", methods=["DELETE"])
@token_required
def unmute_channel(cid):
    pref = NotificationPreference.query.filter_by(
        user_id=g.user.id, channel_id=cid
    ).first()
    if pref:
        pref.muted = False
        pref.muted_until = None
        db.session.commit()
    return jsonify(ok=True)


# ── 13. Mobile Optimization Helpers ─────────────────────────────────────
@community_bp.route("/api/community/servers/<int:sid>/compact", methods=["GET"])
@token_required
def get_compact_server(sid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    member = cc.member_of(sid)
    if member is None:
        return jsonify(error="You are not a member of this server."), 403

    channels = Channel.query.filter_by(server_id=sid).order_by(Channel.position, Channel.id).all()
    roles = ServerRole.query.filter_by(server_id=sid).order_by(ServerRole.rank.desc()).all()
    member_count = _member_count(sid)

    return jsonify(
        server={
            "id": server.id,
            "name": server.name,
            "slug": server.slug,
            "description": server.description,
            "icon_url": server.icon_url,
            "owner_id": server.owner_id,
            "members": member_count,
        },
        channels=[{
            "id": c.id,
            "name": c.name,
            "kind": c.kind,
            "position": c.position,
        } for c in channels],
        roles=[r.to_dict() for r in roles],
        me=member.to_dict(),
        my_permissions=cc.effective_permissions(member),
    )


@community_bp.route("/api/community/channels/<int:cid>/messages/mobile", methods=["GET"])
@token_required
def list_messages_mobile(cid):
    channel = Channel.query.get(cid)
    if channel is None:
        return jsonify(error="Channel not found"), 404
    member = cc.member_of(channel.server_id)
    if member is None or not cc.can(member, Perm.READ):
        return jsonify(error="You cannot view this channel."), 403

    after = request.args.get("after", type=int, default=0)
    query = Message.query.filter(
        Message.channel_id == cid,
        Message.deleted_at.is_(None),
        Message.flagged.is_(False),
    )
    if after:
        query = query.filter(Message.id > after)
    msgs = query.order_by(Message.id.asc()).limit(200).all()

    compact_msgs = []
    for m in msgs:
        compact_msgs.append({
            "id": m.id,
            "author_id": m.author_id,
            "author_name": m.author.name if m.author else "unknown",
            "body": m.body[:500],
            "kind": m.kind,
            "flagged": m.flagged,
            "edited_at": m.edited_at.isoformat() if m.edited_at else None,
            "created_at": m.created_at.isoformat() if m.created_at else None,
        })
    return jsonify(messages=compact_msgs)


# ── 14. Account Recovery ────────────────────────────────────────────────
from ..models import OtpCode as _OtpCode


@community_bp.route("/api/auth/account-recovery", methods=["POST"])
def initiate_account_recovery():
    body = request.get_json(silent=True) or {}
    email = (body.get("email") or "").strip().lower()
    if not email:
        return jsonify(error="Email is required."), 400

    user = User.query.filter_by(email=email).first()
    if user is None:
        return jsonify(ok=True, message="If an account exists, a recovery code has been sent.")

    code = f"{secrets.randbelow(900000) + 100000}"
    otp = _OtpCode(
        user_id=user.id,
        code_hash=hashlib.sha256(code.encode()).hexdigest(),
        purpose="account_recovery",
        expires_at=datetime.utcnow() + timedelta(minutes=15),
    )
    db.session.add(otp)
    db.session.commit()

    cc.notify(user.id, "security", "Account Recovery Code",
              f"Your recovery code is: {code}", "/auth/login")
    log_audit(user.id, "account_recovery_initiated",
              metadata={"email": email})
    return jsonify(ok=True, message="If an account exists, a recovery code has been sent.")


@community_bp.route("/api/auth/account-recovery/verify", methods=["POST"])
def verify_account_recovery():
    body = request.get_json(silent=True) or {}
    email = (body.get("email") or "").strip().lower()
    code = (body.get("code") or "").strip()

    if not email or not code:
        return jsonify(error="Email and code are required."), 400

    user = User.query.filter_by(email=email).first()
    if user is None:
        return jsonify(error="Invalid recovery code."), 400

    code_hash = hashlib.sha256(code.encode()).hexdigest()
    otp = _OtpCode.query.filter_by(
        user_id=user.id, code_hash=code_hash, purpose="account_recovery"
    ).first()

    if otp is None or (otp.expires_at and otp.expires_at < datetime.utcnow()):
        return jsonify(error="Invalid or expired recovery code."), 400

    reset_token = secrets.token_urlsafe(48)
    from ..models import AppSetting
    setting = AppSetting(
        key=f"recovery_reset_{user.id}",
        value=reset_token,
    )
    db.session.add(setting)
    db.session.delete(otp)
    db.session.commit()

    log_audit(user.id, "account_recovery_verified", metadata={"email": email})
    return jsonify(ok=True, reset_token=reset_token)


@community_bp.route("/api/auth/account-recovery/reset", methods=["POST"])
def reset_account_password():
    body = request.get_json(silent=True) or {}
    reset_token = (body.get("reset_token") or "").strip()
    new_password = (body.get("new_password") or "").strip()

    if not reset_token or not new_password:
        return jsonify(error="Reset token and new password are required."), 400
    if len(new_password) < 8:
        return jsonify(error="Password must be at least 8 characters."), 400

    from ..models import AppSetting
    setting = AppSetting.query.filter(
        AppSetting.key.like("recovery_reset_%"),
        AppSetting.value == reset_token,
    ).first()

    if setting is None:
        return jsonify(error="Invalid or expired reset token."), 400

    user_id = int(setting.key.replace("recovery_reset_", ""))
    user = User.query.get(user_id)
    if user is None:
        return jsonify(error="User not found."), 400

    user.set_password(new_password)
    db.session.delete(setting)
    db.session.commit()

    log_audit(user.id, "password_reset_via_recovery")
    return jsonify(ok=True)


# ── 15. Default Permission Improvements ─────────────────────────────────
@community_bp.route("/api/community/servers/<int:sid>/init-default-roles", methods=["POST"])
@token_required
def init_default_roles(sid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    _, err, status = _require_perm(server, Perm.MANAGE_SERVER)
    if err:
        return err, status

    created = []
    existing_names = {r.name for r in ServerRole.query.filter_by(server_id=sid).all()}

    if "Moderator" not in existing_names:
        mod_role = ServerRole(
            server_id=sid,
            name="Moderator",
            rank=50,
            permissions=Perm.MODERATOR,
            color="#e91e63",
        )
        db.session.add(mod_role)
        created.append("Moderator")

    if "Member" not in existing_names:
        member_role = ServerRole(
            server_id=sid,
            name="Member",
            rank=5,
            permissions=Perm.DEFAULT_MEMBER,
            color="#4caf50",
        )
        db.session.add(member_role)
        created.append("Member")

    db.session.commit()
    return jsonify(ok=True, created=created)


# ── 16. Onboarding Completion Check (get_server enhancement) ────────────
@community_bp.route("/api/community/servers/<int:sid>/onboarding-status", methods=["GET"])
@token_required
def get_onboarding_status(sid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404
    member = cc.member_of(sid)
    if member is None:
        return jsonify(error="You are not a member of this server."), 403

    steps = OnboardingStep.query.filter_by(server_id=sid).order_by(OnboardingStep.step_order).all()
    completed = bool(getattr(member, "onboarding_completed", False))

    return jsonify(
        onboarding_required=bool(steps) and not completed,
        onboarding_completed=completed,
        steps=[s.to_dict() for s in steps],
    )


# ── 17. Impostor Detection ──────────────────────────────────────────────
@community_bp.route("/api/community/servers/<int:sid>/similarity", methods=["GET"])
@token_required
def check_server_similarity(sid):
    server = _server_or_404(sid)
    if server is None:
        return jsonify(error="Server not found"), 404

    all_servers = CommunityServer.query.filter(CommunityServer.id != sid).all()
    warnings = []
    for other in all_servers:
        dist = _levenshtein(server.name.lower(), other.name.lower())
        if dist <= 2:
            warnings.append({
                "server_id": other.id,
                "server_name": other.name,
                "edit_distance": dist,
                "is_verified": other.is_verified,
            })

    warnings.sort(key=lambda w: w["edit_distance"])
    return jsonify(warnings=warnings, similarity_warning=len(warnings) > 0)


# ── Verification enforcement on join_by_invite (background check) ───────
# Raid detection: if >10 joins in 60 seconds, auto-lock
_join_timestamps = {}  # server_id -> list of timestamps


def _check_raid(server_id):
    now = datetime.utcnow()
    timestamps = _join_timestamps.setdefault(server_id, [])
    timestamps.append(now)
    _join_timestamps[server_id] = [t for t in timestamps if (now - t).total_seconds() < 60]
    if len(_join_timestamps[server_id]) > 10:
        server = CommunityServer.query.get(server_id)
        if server and not getattr(server, "is_raid_locked", False):
            server.is_raid_locked = True
            db.session.commit()
            log_audit(None, "auto_raid_lock", target_id=server_id,
                      metadata={"joins_in_60s": len(_join_timestamps[server_id])})
            docs_service.write_event(
                "auto_raid_lock",
                {"target": server_id, "joins": len(_join_timestamps[server_id])},
            )
            _join_timestamps[server_id] = []
            return True
    return False
