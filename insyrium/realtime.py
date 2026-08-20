"""Insyrium Realtime — Socket.IO layer for the community.

Adds live chat delivery, typing indicators, presence, live voice-presence and
WebRTC signaling relay for voice channels and direct calls. Media never passes
through the server — only signaling does (server = control plane).

Rooms:
  user:{id}      — private room for a user (DMs, calls, notifications)
  server:{id}    — all connected members of a server (presence, voice)
  channel:{id}   — members currently viewing a text channel (chat, typing)
  dm:{id}        — both participants of a DM thread
"""

import time

import jwt as pyjwt
from flask import current_app, request
from flask_socketio import emit, join_room, leave_room

from .extensions import db, socketio
from .models import Channel, DmThread, ServerMember, User

# ── In-memory realtime state ─────────────────────────────────────────────
_sid_to_user = {}       # sid -> user_id
_user_sids = {}         # user_id -> set(sid)   (multi-tab support)
_typing_rooms = {}      # channel_id -> set(user_id) currently typing


def _decode_user(token):
    try:
        payload = pyjwt.decode(
            token, current_app.config["JWT_SECRET_KEY"], algorithms=["HS256"]
        )
    except pyjwt.PyJWTError:
        return None
    user = User.query.get(int(payload.get("sub")))
    if user is None or user.status != "active":
        return None
    return user


def _register_sid(sid, user):
    _sid_to_user[sid] = user.id
    _user_sids.setdefault(user.id, set()).add(sid)


def _drop_sid(sid):
    user_id = _sid_to_user.pop(sid, None)
    if user_id is None:
        return None
    sids = _user_sids.get(user_id)
    if sids is not None:
        sids.discard(sid)
        if not sids:
            _user_sids.pop(user_id, None)
    return user_id


# ── Connect / disconnect ─────────────────────────────────────────────────
@socketio.on("connect")
def on_connect(auth):
    token = (auth or {}).get("token")
    if not token:
        return False
    user = _decode_user(token)
    if user is None:
        return False
    _register_sid(request.sid, user)
    join_room(f"user:{user.id}")

    # Join all servers the user belongs to (presence/voice rooms).
    servers = ServerMember.query.filter_by(user_id=user.id).all()
    for member in servers:
        join_room(f"server:{member.server_id}")

    # Tell this client who else is online (seed for member presence dots).
    emit("presence:init", {"online": sorted(_user_sids.keys())})
    # Announce the new connection to everyone in their servers.
    for member in servers:
        emit("presence:set", {"user_id": user.id, "online": True},
             to=f"server:{member.server_id}")
    return True


@socketio.on("disconnect")
def on_disconnect():
    user_id = _drop_sid(request.sid)
    if user_id is None:
        return
    # Remove from any typing sets / voice state handled implicitly via presence.
    for cid, users in list(_typing_rooms.items()):
        users.discard(user_id)
        if not users:
            _typing_rooms.pop(cid, None)
    # If they still have another tab open, stay "online".
    if user_id in _user_sids:
        return
    servers = ServerMember.query.filter_by(user_id=user_id).all()
    for member in servers:
        emit("presence:set", {"user_id": user_id, "online": False},
             to=f"server:{member.server_id}")


def _me():
    return _sid_to_user.get(request.sid)


# ── Chat room management ─────────────────────────────────────────────────
@socketio.on("channel:join")
def on_channel_join(data):
    cid = data.get("channel_id")
    if not cid:
        return
    channel = Channel.query.get(cid)
    if channel is None:
        return
    member = ServerMember.query.filter_by(server_id=channel.server_id,
                                          user_id=_me()).first()
    if member is None:
        return
    join_room(f"channel:{cid}")


@socketio.on("channel:leave")
def on_channel_leave(data):
    leave_room(f"channel:{data.get('channel_id')}")


@socketio.on("dm:join")
def on_dm_join(data):
    tid = data.get("thread_id")
    if not tid:
        return
    thread = DmThread.query.get(tid)
    if thread is None:
        return
    if _me() not in (thread.user_a, thread.user_b):
        return
    join_room(f"dm:{tid}")


@socketio.on("dm:leave")
def on_dm_leave(data):
    leave_room(f"dm:{data.get('thread_id')}")


# ── Typing indicators ────────────────────────────────────────────────────
@socketio.on("typing")
def on_typing(data):
    cid = data.get("channel_id")
    uid = _me()
    if not cid or uid is None:
        return
    _typing_rooms.setdefault(cid, set()).add(uid)
    user = User.query.get(uid)
    emit("typing:set", {"channel_id": cid, "user_id": uid,
                        "name": user.name if user else "unknown"},
         to=f"channel:{cid}")


@socketio.on("typing:stop")
def on_typing_stop(data):
    cid = data.get("channel_id")
    uid = _me()
    if not cid or uid is None:
        return
    _typing_rooms.get(cid, set()).discard(uid)


# ── Voice presence (live) ────────────────────────────────────────────────
@socketio.on("voice:join")
def on_voice_join(data):
    cid = data.get("channel_id")
    uid = _me()
    if not cid or uid is None:
        return
    channel = Channel.query.get(cid)
    if channel is None or channel.kind != "voice":
        return
    member = ServerMember.query.filter_by(server_id=channel.server_id,
                                          user_id=uid).first()
    if member is None:
        return
    _broadcast_voice(channel.server_id)


@socketio.on("voice:state")
def on_voice_state(data):
    """Relay mic/speaker state for the caller's current voice channel."""
    cid = data.get("channel_id")
    uid = _me()
    if not cid or uid is None:
        return
    channel = Channel.query.get(cid)
    if channel is None:
        return
    payload = {
        "channel_id": cid,
        "user_id": uid,
        "muted": bool(data.get("muted")),
        "deafened": bool(data.get("deafened")),
    }
    emit("voice:state", payload, to=f"server:{channel.server_id}")


# ── WebRTC signaling relay (voice channels + direct calls) ───────────────
@socketio.on("signal")
def on_signal(data):
    """Relay a WebRTC signaling message to another connected user.

    data: {to: user_id, kind: 'offer'|'answer'|'candidate'|'ring'|'accept'|
           'decline'|'hangup', call: {channel_id}|{thread_id}|{direct}, ...}
    """
    target = data.get("to")
    uid = _me()
    if not target or uid is None:
        return
    if target == uid:
        return
    sender = User.query.get(uid)
    payload = dict(data)
    payload["from"] = uid
    payload["from_name"] = sender.name if sender else "unknown"
    emit("signal", payload, to=f"user:{target}")


# ── Public broadcast helpers (called from REST routes) ───────────────────
def emit_channel_message(message_dict):
    """Broadcast a newly persisted channel message to the channel room."""
    socketio.emit("chat:new", message_dict, to=f"channel:{message_dict['channel_id']}")


def emit_channel_delete(channel_id, message_id):
    socketio.emit("chat:delete", {"channel_id": channel_id, "message_id": message_id},
                  to=f"channel:{channel_id}")


def emit_dm_message(thread_id, message_dict):
    socketio.emit("dm:new", {"thread_id": thread_id, "message": message_dict},
                  to=f"dm:{thread_id}")


def emit_notification(user_id, notification):
    socketio.emit("notif:new", notification, to=f"user:{user_id}")


# ── Voice presence shared with REST poll ─────────────────────────────────
_voice_members = {}  # channel_id -> {user_id: {"muted": bool}}


def voice_members(channel_id):
    return _voice_members.get(channel_id, {})


def voice_add(channel_id, user_id):
    _voice_members.setdefault(channel_id, {})[user_id] = {"muted": False}


def voice_remove(channel_id, user_id):
    room = _voice_members.get(channel_id)
    if room and user_id in room:
        room.pop(user_id)
    if not room:
        _voice_members.pop(channel_id, None)


def voice_snapshot():
    """Global snapshot of every voice channel, same shape as `voice:update`.

    Returns {str_channel_id: [{user_id, name, email}, ...]} so the REST poll
    fallback on the client matches the live broadcast payload.
    """
    out = {}
    for ch_id, room in _voice_members.items():
        if not room:
            continue
        channel = Channel.query.get(ch_id)
        if channel is None:
            continue
        ids = list(room.keys())
        users = User.query.filter(User.id.in_(ids)).all()
        out[str(ch_id)] = [
            {"user_id": u.id, "name": u.name, "email": u.email} for u in users
        ]
    return out


def broadcast_voice(server_id):
    """Send the live voice member list to a server room (public)."""
    _broadcast_voice(server_id)


def _broadcast_voice(server_id):
    """Send the live voice member list to a server room."""
    channels = Channel.query.filter_by(server_id=server_id, kind="voice").all()
    out = {}
    for ch in channels:
        ids = list(_voice_members.get(ch.id, {}).keys())
        if ids:
            users = User.query.filter(User.id.in_(ids)).all()
            out[str(ch.id)] = [
                {"user_id": u.id, "name": u.name, "email": u.email} for u in users
            ]
    socketio.emit("voice:update", {"server_id": server_id, "channels": out},
                  to=f"server:{server_id}")


def server_voice_state(server_id):
    """Non-broadcast snapshot for REST poll fallback."""
    channels = Channel.query.filter_by(server_id=server_id, kind="voice").all()
    out = {}
    for ch in channels:
        ids = list(_voice_members.get(ch.id, {}).keys())
        if ids:
            users = User.query.filter(User.id.in_(ids)).all()
            out[str(ch.id)] = [
                {"user_id": u.id, "name": u.name, "email": u.email} for u in users
            ]
    return out
