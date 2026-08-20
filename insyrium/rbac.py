"""RBAC decorators (Section 7) plus authentication decorators."""

from functools import wraps

import jwt as pyjwt
from flask import g, jsonify, request, current_app

from .models import User

ROLE_RANK = {
    "user": 0,
    "admin_support": 1,
    "admin_content": 2,
    "admin_platform": 3,
    "supreme_admin": 4,
}

RANK_ROLE = {v: k for k, v in ROLE_RANK.items()}


def token_required(view_func):
    """Validate the Bearer access token and load g.user."""

    @wraps(view_func)
    def wrapped(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return jsonify(error="Missing access token", code="no_token"), 401

        token = header[7:]
        try:
            payload = pyjwt.decode(
                token,
                current_app.config["JWT_SECRET_KEY"],
                algorithms=["HS256"],
            )
        except pyjwt.ExpiredSignatureError:
            return (
                jsonify(
                    error="Access token expired",
                    code="token_expired",
                ),
                401,
            )
        except pyjwt.InvalidTokenError:
            return jsonify(error="Invalid access token", code="bad_token"), 401

        user = User.query.get(int(payload.get("sub")))
        if user is None or user.status != "active":
            return jsonify(error="Account unavailable", code="account_unavailable"), 401

        g.user = user
        g.access_payload = payload
        return view_func(*args, **kwargs)

    return wrapped


def step_up_required(view_func):
    """Require a short-lived step-up token in the X-Step-Up-Token header."""

    @wraps(view_func)
    @token_required
    def wrapped(*args, **kwargs):
        token = request.headers.get("X-Step-Up-Token", "")
        if not token:
            return (
                jsonify(error="Step-up verification required", code="step_up_required"),
                403,
            )
        try:
            payload = pyjwt.decode(
                token,
                current_app.config["JWT_SECRET_KEY"],
                algorithms=["HS256"],
            )
        except pyjwt.PyJWTError:
            return jsonify(error="Step-up token invalid", code="step_up_required"), 403

        if payload.get("scope") != "step_up" or payload.get("sub") != str(g.user.id):
            return jsonify(error="Step-up token invalid", code="step_up_required"), 403

        return view_func(*args, **kwargs)

    return wrapped


def require_role(min_role):
    """Allow the route only if the caller's rank >= the required rank."""

    def decorator(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            user_rank = ROLE_RANK.get(g.user.role.name, -1)
            if user_rank < ROLE_RANK.get(min_role, 0):
                return jsonify(error="Insufficient privileges"), 403
            return view_func(*args, **kwargs)

        return wrapped

    return decorator


def require_supreme(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if g.user.role.name != "supreme_admin":
            return jsonify(error="Supreme Admin access required"), 403
        return view_func(*args, **kwargs)

    return wrapped
