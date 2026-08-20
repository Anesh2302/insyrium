"""Community permission evaluation, notifications and spam detection."""

import secrets
from datetime import datetime, timedelta

from flask import g, request

from ..extensions import db
from ..models import (
    Channel,
    CommunityServer,
    Message,
    Notification,
    Perm,
    ServerMember,
    ServerRole,
    User,
)


def member_of(server_id, user_id=None):
    user_id = user_id or g.user.id
    return ServerMember.query.filter_by(server_id=server_id, user_id=user_id).first()


def default_server():
    return CommunityServer.query.filter_by(slug="insyrium-community").first()


def ensure_default_community(join_user=None):
    """Make sure the shared 'Insyrium Community' server exists, with a sane
    channel/role layout, and that the given (or every active) user belongs."""
    server = default_server()
    if server is None:
        owner = User.query.order_by(User.id.asc()).first()
        if owner is None:
            return None
        server = CommunityServer(
            name="Insyrium Community",
            slug="insyrium-community",
            description="Everyone is welcome — chat, share and get support.",
            owner_id=owner.id,
            invite_code=secrets.token_urlsafe(8),
            is_verified=True,
        )
        db.session.add(server)
        db.session.flush()

        everyone = ServerRole(
            server_id=server.id, name="@everyone", rank=0,
            permissions=Perm.DEFAULT_MEMBER, color="#99aab5", is_default=True,
        )
        owner_role = ServerRole(
            server_id=server.id, name="Owner", rank=100,
            permissions=Perm.OWNER, color="#f9a825", is_default=False,
        )
        db.session.add_all([everyone, owner_role])
        db.session.flush()

        layout = [
            ("welcome", "text", "Welcome! Introduce yourself and read the rules."),
            ("general", "text", "General chat — say hello."),
            ("announcements", "text", "Official announcements."),
            ("support", "text", "Need help? Ask here."),
            ("lounge", "voice", ""),
        ]
        for pos, (name, kind, topic) in enumerate(layout):
            db.session.add(Channel(
                server_id=server.id, name=name, kind=kind, topic=topic,
                position=pos, created_by=owner.id,
            ))

        # Backfill every active user as a member so nobody is locked out.
        for u in User.query.filter_by(status="active").all():
            role = owner_role if u.id == owner.id else everyone
            _join(server.id, u.id, role.id)
        db.session.commit()
        return server

    if join_user is not None:
        everyone = ServerRole.query.filter_by(
            server_id=server.id, is_default=True
        ).first()
        _join(server.id, join_user.id, everyone.id if everyone else None)
        db.session.commit()
    return server


def _join(server_id, user_id, role_id):
    if ServerMember.query.filter_by(server_id=server_id, user_id=user_id).first():
        return
    db.session.add(
        ServerMember(server_id=server_id, user_id=user_id, role_id=role_id)
    )


def ensure_user_in_default(user):
    """Auto-join a single user to the shared community (used on activation)."""
    if user is None or user.status != "active":
        return
    ensure_default_community(join_user=user)


def effective_permissions(member):
    """Permissions = role permissions (default role if the member has no custom role)."""
    if member is None:
        return 0
    if member.role_id:
        return member.role.permissions or 0
    return Perm.DEFAULT_MEMBER


def can(member, perm):
    return bool(effective_permissions(member) & perm)


def notify(user_id, kind, title, body="", link=""):
    notification = Notification(
        user_id=user_id, kind=kind, title=title, body=body, link=link
    )
    db.session.add(notification)
    db.session.commit()
    try:
        from ..realtime import emit_notification
        emit_notification(user_id, notification.to_dict())
    except Exception:
        pass  # never let a push failure break message handling
    return True


def is_muted(member):
    return member is not None and member.muted_until and member.muted_until > datetime.utcnow()


def is_spam(author_id, server_id, channel_id, text, window_seconds=8, max_in_window=6):
    """Per-user flood detection + exact-duplicate detection.

    Message.created_at is written by MySQL NOW() (DB-server local time), so
    windows are computed with datetime.now() — NOT datetime.utcnow() — or the
    flood window would be widened by the DB server's UTC offset.
    """
    since = datetime.now() - timedelta(seconds=window_seconds)
    recent = Message.query.filter(
        Message.channel_id == channel_id,
        Message.author_id == author_id,
        Message.created_at >= since,
    ).count()
    if recent >= max_in_window:
        return True, f"Rate limited ({max_in_window} messages/{window_seconds}s)"

    dup = Message.query.filter(
        Message.channel_id == channel_id,
        Message.author_id == author_id,
        Message.body == text,
        Message.created_at >= datetime.now() - timedelta(seconds=30),
    ).first()
    if dup:
        return True, "Duplicate message"
    return False, None


def user_ip():
    return request.remote_addr or ""
