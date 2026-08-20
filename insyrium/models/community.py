"""Insyrium Community — Discord-style servers, channels, messaging, moderation,
notifications and private (encrypted at rest) DMs.

Secure-by-default permission model:
  * the default member role carries only read/send/embed/attach permissions
  * management / moderation / mention-all / invite-creation are opt-in grants
"""

import json
from datetime import datetime

from ..extensions import db


class Perm:
    """Community permission flags (bitmask stored on roles)."""

    VIEW = 1 << 0          # see channels
    READ = 1 << 1          # read messages
    SEND = 1 << 2          # send messages
    EMBED = 1 << 3         # post clickable links
    ATTACH = 1 << 4        # upload attachments
    CREATE_INVITE = 1 << 5
    MENTION_ALL = 1 << 6
    MANAGE_MESSAGES = 1 << 7
    MANAGE_CHANNELS = 1 << 8
    MANAGE_ROLES = 1 << 9
    MANAGE_SERVER = 1 << 10
    KICK = 1 << 11
    BAN = 1 << 12
    MUTE = 1 << 13
    MODERATE = 1 << 14
    MANAGE_BOTS = 1 << 15
    VIEW_AUDIT = 1 << 16

    # Least-privilege default for ordinary members (fixes over-permissive defaults).
    DEFAULT_MEMBER = VIEW | READ | SEND | EMBED | ATTACH
    MODERATOR = DEFAULT_MEMBER | MANAGE_MESSAGES | MODERATE | MUTE | KICK
    ADMIN = MODERATOR | MANAGE_CHANNELS | MANAGE_ROLES | BAN | VIEW_AUDIT | MENTION_ALL
    OWNER = ADMIN | MANAGE_SERVER | MANAGE_BOTS | CREATE_INVITE

    NAMES = {
        "view": VIEW, "read": READ, "send": SEND, "embed": EMBED,
        "attach": ATTACH, "create_invite": CREATE_INVITE, "mention_all": MENTION_ALL,
        "manage_messages": MANAGE_MESSAGES, "manage_channels": MANAGE_CHANNELS,
        "manage_roles": MANAGE_ROLES, "manage_server": MANAGE_SERVER,
        "kick": KICK, "ban": BAN, "mute": MUTE, "moderate": MODERATE,
        "manage_bots": MANAGE_BOTS, "view_audit": VIEW_AUDIT,
    }


class CommunityServer(db.Model):
    __tablename__ = "community_servers"

    id = db.Column(db.BigInteger, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    slug = db.Column(db.String(100), unique=True, nullable=False, index=True)
    description = db.Column(db.String(500), default="")
    icon_url = db.Column(db.String(500))
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    invite_code = db.Column(db.String(24), unique=True, nullable=False, index=True)
    owner_id = db.Column(db.BigInteger, db.ForeignKey("users.id"), nullable=False)
    retention_days = db.Column(db.Integer, default=0, nullable=False)  # 0 = keep forever
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    owner = db.relationship("User", foreign_keys=[owner_id])

    def to_dict(self, member_count=None):
        return {
            "id": self.id,
            "name": self.name,
            "slug": self.slug,
            "description": self.description,
            "icon_url": self.icon_url,
            "is_verified": self.is_verified,
            "owner_id": self.owner_id,
            "invite_code": self.invite_code,
            "retention_days": self.retention_days,
            "members": member_count,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class ServerRole(db.Model):
    __tablename__ = "community_roles"

    id = db.Column(db.BigInteger, primary_key=True)
    server_id = db.Column(db.BigInteger, db.ForeignKey("community_servers.id"), nullable=False, index=True)
    name = db.Column(db.String(50), nullable=False)
    rank = db.Column(db.Integer, default=0, nullable=False)
    permissions = db.Column(db.BigInteger, default=Perm.DEFAULT_MEMBER, nullable=False)
    color = db.Column(db.String(7), default="#99aab5")
    is_default = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    def to_dict(self):
        return {
            "id": self.id,
            "server_id": self.server_id,
            "name": self.name,
            "rank": self.rank,
            "permissions": self.permissions,
            "color": self.color,
            "is_default": self.is_default,
        }


class ServerMember(db.Model):
    __tablename__ = "community_members"
    __table_args__ = (db.UniqueConstraint("server_id", "user_id", name="uq_member_server_user"),)

    id = db.Column(db.BigInteger, primary_key=True)
    server_id = db.Column(db.BigInteger, db.ForeignKey("community_servers.id"), nullable=False, index=True)
    user_id = db.Column(db.BigInteger, db.ForeignKey("users.id"), nullable=False, index=True)
    role_id = db.Column(db.BigInteger, db.ForeignKey("community_roles.id"), nullable=True)
    nickname = db.Column(db.String(60))
    is_suspended = db.Column(db.Boolean, default=False, nullable=False)
    muted_until = db.Column(db.DateTime, nullable=True)
    joined_at = db.Column(db.DateTime, server_default=db.func.now())

    user = db.relationship("User", foreign_keys=[user_id])
    role = db.relationship("ServerRole", foreign_keys=[role_id])

    def to_dict(self):
        return {
            "id": self.id,
            "server_id": self.server_id,
            "user_id": self.user_id,
            "username": self.user.name if self.user else None,
            "email": self.user.email if self.user else None,
            "nickname": self.nickname,
            "role_id": self.role_id,
            "is_suspended": self.is_suspended,
            "muted_until": self.muted_until.isoformat() if self.muted_until else None,
            "joined_at": self.joined_at.isoformat() if self.joined_at else None,
        }


class Channel(db.Model):
    __tablename__ = "community_channels"

    id = db.Column(db.BigInteger, primary_key=True)
    server_id = db.Column(db.BigInteger, db.ForeignKey("community_servers.id"), nullable=False, index=True)
    name = db.Column(db.String(60), nullable=False)
    kind = db.Column(db.String(10), default="text", nullable=False)  # text | voice
    topic = db.Column(db.String(300), default="")
    slow_mode_seconds = db.Column(db.Integer, default=0, nullable=False)
    position = db.Column(db.Integer, default=0, nullable=False)
    category_id = db.Column(db.BigInteger, db.ForeignKey("community_categories.id"), nullable=True)
    is_nsfw = db.Column(db.Boolean, default=False, nullable=False)
    created_by = db.Column(db.BigInteger, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    def to_dict(self):
        return {
            "id": self.id,
            "server_id": self.server_id,
            "name": self.name,
            "kind": self.kind,
            "topic": self.topic,
            "slow_mode_seconds": self.slow_mode_seconds,
            "position": self.position,
            "category_id": self.category_id,
            "is_nsfw": self.is_nsfw,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Message(db.Model):
    __tablename__ = "community_messages"

    id = db.Column(db.BigInteger, primary_key=True)
    server_id = db.Column(db.BigInteger, db.ForeignKey("community_servers.id"), nullable=False, index=True)
    channel_id = db.Column(db.BigInteger, db.ForeignKey("community_channels.id"), nullable=False, index=True)
    thread_id = db.Column(db.BigInteger, db.ForeignKey("community_threads.id"), nullable=True, index=True)
    reply_to_id = db.Column(db.BigInteger, db.ForeignKey("community_messages.id"), nullable=True)
    embed_json = db.Column(db.Text, nullable=True)
    author_id = db.Column(db.BigInteger, db.ForeignKey("users.id"), nullable=False, index=True)
    body = db.Column(db.Text, nullable=False)
    kind = db.Column(db.String(10), default="text", nullable=False)  # text | system | notice
    attachment_name = db.Column(db.String(255))
    attachment_size = db.Column(db.Integer)
    link_status = db.Column(db.String(10), default="none")  # none | safe | flagged | blocked
    flagged = db.Column(db.Boolean, default=False, nullable=False)
    deleted_at = db.Column(db.DateTime, nullable=True)
    edited_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now(), index=True)

    author = db.relationship("User", foreign_keys=[author_id])

    def to_dict(self):
        return {
            "id": self.id,
            "server_id": self.server_id,
            "channel_id": self.channel_id,
            "thread_id": self.thread_id,
            "reply_to_id": self.reply_to_id,
            "embed_json": self.embed_json,
            "author_id": self.author_id,
            "author_name": self.author.name if self.author else "unknown",
            "body": self.body,
            "kind": self.kind,
            "attachment_name": self.attachment_name,
            "attachment_size": self.attachment_size,
            "link_status": self.link_status,
            "flagged": self.flagged,
            "deleted_at": self.deleted_at.isoformat() if self.deleted_at else None,
            "edited_at": self.edited_at.isoformat() if self.edited_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class ServerBan(db.Model):
    __tablename__ = "community_bans"

    id = db.Column(db.BigInteger, primary_key=True)
    server_id = db.Column(db.BigInteger, db.ForeignKey("community_servers.id"), nullable=False, index=True)
    user_id = db.Column(db.BigInteger, db.ForeignKey("users.id"), nullable=False, index=True)
    reason = db.Column(db.String(500))
    banned_by = db.Column(db.BigInteger, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())


class Report(db.Model):
    __tablename__ = "community_reports"

    id = db.Column(db.BigInteger, primary_key=True)
    server_id = db.Column(db.BigInteger, db.ForeignKey("community_servers.id"), nullable=False, index=True)
    channel_id = db.Column(db.BigInteger, db.ForeignKey("community_channels.id"), nullable=True)
    message_id = db.Column(db.BigInteger, db.ForeignKey("community_messages.id"), nullable=True)
    reporter_id = db.Column(db.BigInteger, db.ForeignKey("users.id"), nullable=False)
    reason = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(12), default="new", nullable=False)  # new | resolved | dismissed
    handled_by = db.Column(db.BigInteger, nullable=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    reporter = db.relationship("User", foreign_keys=[reporter_id])
    message = db.relationship("Message", foreign_keys=[message_id])

    def to_dict(self):
        return {
            "id": self.id,
            "server_id": self.server_id,
            "channel_id": self.channel_id,
            "message_id": self.message_id,
            "reporter_id": self.reporter_id,
            "reporter_name": self.reporter.name if self.reporter else None,
            "reason": self.reason,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Notification(db.Model):
    __tablename__ = "community_notifications"

    id = db.Column(db.BigInteger, primary_key=True)
    user_id = db.Column(db.BigInteger, db.ForeignKey("users.id"), nullable=False, index=True)
    kind = db.Column(db.String(24), nullable=False)  # mention | reply | dm | mod | report | system
    title = db.Column(db.String(160), nullable=False)
    body = db.Column(db.String(400), default="")
    link = db.Column(db.String(300), default="")
    read_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now(), index=True)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "kind": self.kind,
            "title": self.title,
            "body": self.body,
            "link": self.link,
            "read_at": self.read_at.isoformat() if self.read_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class DmThread(db.Model):
    __tablename__ = "community_dm_threads"
    __table_args__ = (db.UniqueConstraint("user_a", "user_b", name="uq_dm_pair"),)

    id = db.Column(db.BigInteger, primary_key=True)
    user_a = db.Column(db.BigInteger, db.ForeignKey("users.id"), nullable=False)
    user_b = db.Column(db.BigInteger, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())


class DmMessage(db.Model):
    __tablename__ = "community_dm_messages"

    id = db.Column(db.BigInteger, primary_key=True)
    thread_id = db.Column(db.BigInteger, db.ForeignKey("community_dm_threads.id"), nullable=False, index=True)
    sender_id = db.Column(db.BigInteger, db.ForeignKey("users.id"), nullable=False, index=True)
    ciphertext = db.Column(db.Text, nullable=False)   # encrypted at rest (Fernet)
    created_at = db.Column(db.DateTime, server_default=db.func.now(), index=True)


class MessageReaction(db.Model):
    __tablename__ = "community_reactions"
    __table_args__ = (
        db.UniqueConstraint("message_id", "user_id", "emoji", name="uq_reaction_message_user_emoji"),
    )

    id = db.Column(db.BigInteger, primary_key=True)
    message_id = db.Column(db.BigInteger, db.ForeignKey("community_messages.id"), nullable=False, index=True)
    user_id = db.Column(db.BigInteger, db.ForeignKey("users.id"), nullable=False, index=True)
    emoji = db.Column(db.String(32), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    def to_dict(self):
        return {
            "id": self.id,
            "message_id": self.message_id,
            "user_id": self.user_id,
            "emoji": self.emoji,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Thread(db.Model):
    __tablename__ = "community_threads"

    id = db.Column(db.BigInteger, primary_key=True)
    parent_channel_id = db.Column(db.BigInteger, db.ForeignKey("community_channels.id"), nullable=False, index=True)
    server_id = db.Column(db.BigInteger, db.ForeignKey("community_servers.id"), nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    creator_id = db.Column(db.BigInteger, db.ForeignKey("users.id"), nullable=False)
    message_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    last_message_at = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "parent_channel_id": self.parent_channel_id,
            "server_id": self.server_id,
            "name": self.name,
            "creator_id": self.creator_id,
            "message_count": self.message_count,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_message_at": self.last_message_at.isoformat() if self.last_message_at else None,
        }


class ChannelCategory(db.Model):
    __tablename__ = "community_categories"

    id = db.Column(db.BigInteger, primary_key=True)
    server_id = db.Column(db.BigInteger, db.ForeignKey("community_servers.id"), nullable=False, index=True)
    name = db.Column(db.String(50), nullable=False)
    position = db.Column(db.Integer, default=0)

    def to_dict(self):
        return {
            "id": self.id,
            "server_id": self.server_id,
            "name": self.name,
            "position": self.position,
        }


class PinnedMessage(db.Model):
    __tablename__ = "community_pinned_messages"

    id = db.Column(db.BigInteger, primary_key=True)
    message_id = db.Column(db.BigInteger, db.ForeignKey("community_messages.id"), unique=True, nullable=False)
    channel_id = db.Column(db.BigInteger, db.ForeignKey("community_channels.id"), nullable=False, index=True)
    pinned_by = db.Column(db.BigInteger, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    def to_dict(self):
        return {
            "id": self.id,
            "message_id": self.message_id,
            "channel_id": self.channel_id,
            "pinned_by": self.pinned_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class CustomEmoji(db.Model):
    __tablename__ = "community_emoji"
    __table_args__ = (
        db.UniqueConstraint("server_id", "name", name="uq_emoji_server_name"),
    )

    id = db.Column(db.BigInteger, primary_key=True)
    server_id = db.Column(db.BigInteger, db.ForeignKey("community_servers.id"), nullable=False, index=True)
    name = db.Column(db.String(32), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    creator_id = db.Column(db.BigInteger, db.ForeignKey("users.id"), nullable=False)
    is_animated = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    def to_dict(self):
        return {
            "id": self.id,
            "server_id": self.server_id,
            "name": self.name,
            "url": self.url,
            "is_animated": self.is_animated,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class ChannelPermissionOverride(db.Model):
    __tablename__ = "community_channel_overrides"

    id = db.Column(db.BigInteger, primary_key=True)
    channel_id = db.Column(db.BigInteger, db.ForeignKey("community_channels.id"), nullable=False, index=True)
    role_id = db.Column(db.BigInteger, db.ForeignKey("community_roles.id"), nullable=True, index=True)
    user_id = db.Column(db.BigInteger, db.ForeignKey("users.id"), nullable=True, index=True)
    allow = db.Column(db.BigInteger, default=0)
    deny = db.Column(db.BigInteger, default=0)

    def to_dict(self):
        return {
            "id": self.id,
            "channel_id": self.channel_id,
            "role_id": self.role_id,
            "user_id": self.user_id,
            "allow": self.allow,
            "deny": self.deny,
        }


class UserStatus(db.Model):
    __tablename__ = "community_user_statuses"

    id = db.Column(db.BigInteger, primary_key=True)
    user_id = db.Column(db.BigInteger, db.ForeignKey("users.id"), unique=True, nullable=False)
    status = db.Column(db.String(20), default="online")
    custom_status = db.Column(db.String(128), nullable=True)
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "status": self.status,
            "custom_status": self.custom_status,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class ScheduledEvent(db.Model):
    __tablename__ = "community_events"

    id = db.Column(db.BigInteger, primary_key=True)
    server_id = db.Column(db.BigInteger, db.ForeignKey("community_servers.id"), nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(500), default="")
    channel_id = db.Column(db.BigInteger, db.ForeignKey("community_channels.id"), nullable=True)
    creator_id = db.Column(db.BigInteger, db.ForeignKey("users.id"), nullable=False)
    start_at = db.Column(db.DateTime, nullable=False)
    end_at = db.Column(db.DateTime, nullable=True)
    location = db.Column(db.String(200), default="")
    status = db.Column(db.String(12), default="scheduled")
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    def to_dict(self):
        return {
            "id": self.id,
            "server_id": self.server_id,
            "name": self.name,
            "description": self.description,
            "channel_id": self.channel_id,
            "creator_id": self.creator_id,
            "start_at": self.start_at.isoformat() if self.start_at else None,
            "end_at": self.end_at.isoformat() if self.end_at else None,
            "location": self.location,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class AutoModRule(db.Model):
    __tablename__ = "community_automod_rules"

    id = db.Column(db.BigInteger, primary_key=True)
    server_id = db.Column(db.BigInteger, db.ForeignKey("community_servers.id"), nullable=False, index=True)
    name = db.Column(db.String(50), nullable=False)
    trigger_type = db.Column(db.String(20), nullable=False)
    trigger_value = db.Column(db.String(500), default="")
    action_type = db.Column(db.String(20), nullable=False)
    action_duration_minutes = db.Column(db.Integer, default=0)
    created_by = db.Column(db.BigInteger, db.ForeignKey("users.id"), nullable=False)
    is_enabled = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    def to_dict(self):
        return {
            "id": self.id,
            "server_id": self.server_id,
            "name": self.name,
            "trigger_type": self.trigger_type,
            "trigger_value": self.trigger_value,
            "action_type": self.action_type,
            "action_duration_minutes": self.action_duration_minutes,
            "created_by": self.created_by,
            "is_enabled": self.is_enabled,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Webhook(db.Model):
    __tablename__ = "community_webhooks"

    id = db.Column(db.BigInteger, primary_key=True)
    server_id = db.Column(db.BigInteger, db.ForeignKey("community_servers.id"), nullable=False, index=True)
    channel_id = db.Column(db.BigInteger, db.ForeignKey("community_channels.id"), nullable=False, index=True)
    name = db.Column(db.String(80), nullable=False)
    avatar_url = db.Column(db.String(500))
    token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    creator_id = db.Column(db.BigInteger, db.ForeignKey("users.id"), nullable=False)
    is_enabled = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    def to_dict(self):
        return {
            "id": self.id,
            "server_id": self.server_id,
            "channel_id": self.channel_id,
            "name": self.name,
            "avatar_url": self.avatar_url,
            "is_enabled": self.is_enabled,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Sticker(db.Model):
    __tablename__ = "community_stickers"

    id = db.Column(db.BigInteger, primary_key=True)
    server_id = db.Column(db.BigInteger, db.ForeignKey("community_servers.id"), nullable=False, index=True)
    name = db.Column(db.String(50), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    creator_id = db.Column(db.BigInteger, db.ForeignKey("users.id"), nullable=False)
    tags = db.Column(db.String(128), default="")
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    def to_dict(self):
        return {
            "id": self.id,
            "server_id": self.server_id,
            "name": self.name,
            "url": self.url,
            "creator_id": self.creator_id,
            "tags": self.tags,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class ServerTemplate(db.Model):
    __tablename__ = "community_server_templates"

    id = db.Column(db.BigInteger, primary_key=True)
    server_id = db.Column(db.BigInteger, db.ForeignKey("community_servers.id"), nullable=False, index=True)
    name = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(500), default="")
    creator_id = db.Column(db.BigInteger, db.ForeignKey("users.id"), nullable=False)
    template_data = db.Column(db.Text, nullable=False)
    usage_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    def to_dict(self):
        return {
            "id": self.id,
            "server_id": self.server_id,
            "name": self.name,
            "description": self.description,
            "creator_id": self.creator_id,
            "usage_count": self.usage_count,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


# ---------------------------------------------------------------------------
# 15 new models — Discord-like features
# ---------------------------------------------------------------------------


class GroupDmThread(db.Model):
    __tablename__ = "community_group_dm_threads"

    id = db.Column(db.BigInteger, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    creator_id = db.Column(db.BigInteger, db.ForeignKey("users.id"), nullable=False)
    icon_url = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "creator_id": self.creator_id,
            "icon_url": self.icon_url,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class GroupDmMember(db.Model):
    __tablename__ = "community_group_dm_members"
    __table_args__ = (db.UniqueConstraint("thread_id", "user_id", name="uq_group_dm_thread_user"),)

    id = db.Column(db.BigInteger, primary_key=True)
    thread_id = db.Column(db.BigInteger, db.ForeignKey("community_group_dm_threads.id"), nullable=False, index=True)
    user_id = db.Column(db.BigInteger, db.ForeignKey("users.id"), nullable=False, index=True)
    nickname = db.Column(db.String(60))
    joined_at = db.Column(db.DateTime, server_default=db.func.now())

    def to_dict(self):
        return {
            "id": self.id,
            "thread_id": self.thread_id,
            "user_id": self.user_id,
            "nickname": self.nickname,
            "joined_at": self.joined_at.isoformat() if self.joined_at else None,
        }


class GroupDmMessage(db.Model):
    __tablename__ = "community_group_dm_messages"

    id = db.Column(db.BigInteger, primary_key=True)
    thread_id = db.Column(db.BigInteger, db.ForeignKey("community_group_dm_threads.id"), nullable=False, index=True)
    sender_id = db.Column(db.BigInteger, db.ForeignKey("users.id"), nullable=False, index=True)
    ciphertext = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    def to_dict(self):
        return {
            "id": self.id,
            "thread_id": self.thread_id,
            "sender_id": self.sender_id,
            "body": self.ciphertext,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class ScreenShare(db.Model):
    __tablename__ = "community_screenshares"

    id = db.Column(db.BigInteger, primary_key=True)
    user_id = db.Column(db.BigInteger, db.ForeignKey("users.id"), nullable=False, index=True)
    channel_id = db.Column(db.BigInteger, db.ForeignKey("community_channels.id"), nullable=False, index=True)
    server_id = db.Column(db.BigInteger, db.ForeignKey("community_servers.id"), nullable=False, index=True)
    title = db.Column(db.String(120), default="Screen Share")
    is_live = db.Column(db.Boolean, default=True)
    viewer_count = db.Column(db.Integer, default=0)
    started_at = db.Column(db.DateTime, server_default=db.func.now())
    ended_at = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "channel_id": self.channel_id,
            "server_id": self.server_id,
            "title": self.title,
            "is_live": self.is_live,
            "viewer_count": self.viewer_count,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "ended_at": self.ended_at.isoformat() if self.ended_at else None,
        }


class StageChannel(db.Model):
    __tablename__ = "community_stage_channels"

    id = db.Column(db.BigInteger, primary_key=True)
    server_id = db.Column(db.BigInteger, db.ForeignKey("community_servers.id"), nullable=False, index=True)
    channel_id = db.Column(db.BigInteger, db.ForeignKey("community_channels.id"), nullable=False, index=True)
    topic = db.Column(db.String(200), default="")
    speaker_ids = db.Column(db.Text, default="[]")
    listener_ids = db.Column(db.Text, default="[]")
    is_live = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    def to_dict(self):
        return {
            "id": self.id,
            "server_id": self.server_id,
            "channel_id": self.channel_id,
            "topic": self.topic,
            "speaker_ids": json.loads(self.speaker_ids) if self.speaker_ids else [],
            "listener_ids": json.loads(self.listener_ids) if self.listener_ids else [],
            "is_live": self.is_live,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class ServerBoost(db.Model):
    __tablename__ = "community_server_boosts"
    __table_args__ = (db.UniqueConstraint("server_id", "user_id", name="uq_server_boost_server_user"),)

    id = db.Column(db.BigInteger, primary_key=True)
    server_id = db.Column(db.BigInteger, db.ForeignKey("community_servers.id"), nullable=False, index=True)
    user_id = db.Column(db.BigInteger, db.ForeignKey("users.id"), nullable=False, index=True)
    tier = db.Column(db.Integer, default=1)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    expires_at = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "server_id": self.server_id,
            "user_id": self.user_id,
            "tier": self.tier,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }


class RichPresence(db.Model):
    __tablename__ = "community_rich_presences"

    id = db.Column(db.BigInteger, primary_key=True)
    user_id = db.Column(db.BigInteger, db.ForeignKey("users.id"), unique=True, nullable=False)
    status_text = db.Column(db.String(128), default="")
    app_name = db.Column(db.String(100), default="")
    app_details = db.Column(db.String(200), default="")
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "status_text": self.status_text,
            "app_name": self.app_name,
            "app_details": self.app_details,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class ForumPost(db.Model):
    __tablename__ = "community_forum_posts"

    id = db.Column(db.BigInteger, primary_key=True)
    channel_id = db.Column(db.BigInteger, db.ForeignKey("community_channels.id"), nullable=False, index=True)
    server_id = db.Column(db.BigInteger, db.ForeignKey("community_servers.id"), nullable=False, index=True)
    author_id = db.Column(db.BigInteger, db.ForeignKey("users.id"), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    body = db.Column(db.Text, nullable=False)
    is_pinned = db.Column(db.Boolean, default=False)
    is_locked = db.Column(db.Boolean, default=False)
    reply_count = db.Column(db.Integer, default=0)
    last_reply_at = db.Column(db.DateTime, nullable=True)
    tags = db.Column(db.String(200), default="")
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    author = db.relationship("User", foreign_keys=[author_id])

    def to_dict(self):
        return {
            "id": self.id,
            "channel_id": self.channel_id,
            "server_id": self.server_id,
            "author_id": self.author_id,
            "author_name": self.author.name if self.author else None,
            "title": self.title,
            "body": self.body,
            "is_pinned": self.is_pinned,
            "is_locked": self.is_locked,
            "reply_count": self.reply_count,
            "last_reply_at": self.last_reply_at.isoformat() if self.last_reply_at else None,
            "tags": self.tags,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class ForumReply(db.Model):
    __tablename__ = "community_forum_replies"

    id = db.Column(db.BigInteger, primary_key=True)
    post_id = db.Column(db.BigInteger, db.ForeignKey("community_forum_posts.id"), nullable=False, index=True)
    author_id = db.Column(db.BigInteger, db.ForeignKey("users.id"), nullable=False)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    author = db.relationship("User", foreign_keys=[author_id])

    def to_dict(self):
        return {
            "id": self.id,
            "post_id": self.post_id,
            "author_id": self.author_id,
            "author_name": self.author.name if self.author else None,
            "body": self.body,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class VerificationLevel(db.Model):
    __tablename__ = "community_verification_levels"

    id = db.Column(db.BigInteger, primary_key=True)
    server_id = db.Column(db.BigInteger, db.ForeignKey("community_servers.id"), unique=True, nullable=False)
    level = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    def to_dict(self):
        return {
            "id": self.id,
            "server_id": self.server_id,
            "level": self.level,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Bot(db.Model):
    __tablename__ = "community_bots"

    id = db.Column(db.BigInteger, primary_key=True)
    user_id = db.Column(db.BigInteger, db.ForeignKey("users.id"), nullable=False, index=True)
    owner_id = db.Column(db.BigInteger, db.ForeignKey("users.id"), nullable=False, index=True)
    name = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(500), default="")
    token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    permissions = db.Column(db.BigInteger, default=0)
    is_public = db.Column(db.Boolean, default=False)
    invite_url = db.Column(db.String(300))
    is_enabled = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "is_public": self.is_public,
            "invite_url": self.invite_url,
            "is_enabled": self.is_enabled,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class OnboardingStep(db.Model):
    __tablename__ = "community_onboarding_steps"

    id = db.Column(db.BigInteger, primary_key=True)
    server_id = db.Column(db.BigInteger, db.ForeignKey("community_servers.id"), nullable=False, index=True)
    step_order = db.Column(db.Integer, nullable=False)
    title = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(300), default="")
    required_role_id = db.Column(db.BigInteger, db.ForeignKey("community_roles.id"), nullable=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    def to_dict(self):
        return {
            "id": self.id,
            "server_id": self.server_id,
            "step_order": self.step_order,
            "title": self.title,
            "description": self.description,
            "required_role_id": self.required_role_id,
        }


class RaidLog(db.Model):
    __tablename__ = "community_raid_logs"

    id = db.Column(db.BigInteger, primary_key=True)
    server_id = db.Column(db.BigInteger, db.ForeignKey("community_servers.id"), nullable=False, index=True)
    trigger_type = db.Column(db.String(20), nullable=False)
    actor_ids = db.Column(db.Text, default="[]")
    action_taken = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    def to_dict(self):
        return {
            "id": self.id,
            "server_id": self.server_id,
            "trigger_type": self.trigger_type,
            "actor_ids": json.loads(self.actor_ids) if self.actor_ids else [],
            "action_taken": self.action_taken,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class NotificationPreference(db.Model):
    __tablename__ = "community_notification_prefs"

    id = db.Column(db.BigInteger, primary_key=True)
    user_id = db.Column(db.BigInteger, db.ForeignKey("users.id"), nullable=False, index=True)
    server_id = db.Column(db.BigInteger, db.ForeignKey("community_servers.id"), nullable=False, index=True)
    channel_id = db.Column(db.BigInteger, db.ForeignKey("community_channels.id"), nullable=True, index=True)
    notify_mentions = db.Column(db.Boolean, default=True)
    notify_replies = db.Column(db.Boolean, default=True)
    notify_dms = db.Column(db.Boolean, default=True)
    notify_events = db.Column(db.Boolean, default=True)
    muted = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "server_id": self.server_id,
            "channel_id": self.channel_id,
            "notify_mentions": self.notify_mentions,
            "notify_replies": self.notify_replies,
            "notify_dms": self.notify_dms,
            "notify_events": self.notify_events,
            "muted": self.muted,
        }


class SessionFingerprint(db.Model):
    __tablename__ = "community_session_fingerprints"

    id = db.Column(db.BigInteger, primary_key=True)
    user_id = db.Column(db.BigInteger, db.ForeignKey("users.id"), nullable=False, index=True)
    fingerprint = db.Column(db.String(64), nullable=False)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(300))
    last_seen = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "fingerprint": self.fingerprint,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
