"""Insyrium Portal — application factory."""

import os

from apscheduler.schedulers.background import BackgroundScheduler
from flask import Flask, render_template, request

from .extensions import db, limiter, mail, socketio
from .security import set_csrf_cookie, security_headers


def create_app(config_object=None):
    from config import Config

    app = Flask(
        __name__,
        static_folder="static",
        template_folder="templates",
    )
    app.config.from_object(config_object or Config)

    # ── Extensions ────────────────────────────────────────────
    db.init_app(app)
    limiter.init_app(app)
    mail.init_app(app)
    socketio.init_app(app)

    # ── Blueprints ─────────────────────────────────────────────
    from .routes.admin import admin_bp
    from .routes.auth import auth_bp
    from .routes.community import community_bp
    from .routes.main import main_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(community_bp)

    # ── Realtime (Socket.IO) ───────────────────────────────────
    # Importing the module registers its event handlers on `socketio`.
    from . import realtime  # noqa: F401

    # ── Security / context ─────────────────────────────────────
    @app.after_request
    def _after(response):
        response = security_headers(response)
        response = set_csrf_cookie(response)
        return response

    @app.context_processor
    def _ctx():
        return {"portal_name": app.config["PORTAL_NAME"]}

    # ── Error handlers ─────────────────────────────────────────
    @app.errorhandler(403)
    def forbidden(e):
        return render_template("errors/403.html"), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def server_error(e):
        db.session.rollback()
        return render_template("errors/500.html"), 500

    # ── CLI ────────────────────────────────────────────────────
    from . import cli

    cli.init_app(app)

    # ── Background alerting (Section 9.3) ──────────────────────
    _start_scheduler(app)

    with app.app_context():
        try:
            db.create_all()
        except Exception:
            app.logger.warning(
                "Could not create tables — check DATABASE_URL env var. "
                "Run: flask --app app init-db"
            )
        _sync_user_columns(app)
        _migrate_settings_keys(app)
        try:
            from .services import community as community_service
            community_service.ensure_default_community()
        except Exception as exc:  # never block boot on seeding
            app.logger.warning("Could not seed default community: %s", exc)

    return app


def _migrate_settings_keys(app):
    """Rename legacy hyphenated settings (e.g. alert-email) to underscore keys."""
    from .models import AppSetting

    legacy = ["portal-name", "allow-registration", "maintenance-mode",
              "default-mfa-for-admins", "alert-email"]
    try:
        for hyphen in legacy:
            underscore = hyphen.replace("-", "_")
            if AppSetting.get(underscore) is None:
                value = AppSetting.get(hyphen)
                if value is not None:
                    AppSetting.set(underscore, value, None)
                    row = AppSetting.query.filter_by(key=hyphen).first()
                    if row:
                        db.session.delete(row)
                        db.session.commit()
        app.logger.info("Settings keys migrated to underscore names")
    except Exception as exc:  # never block boot on a settings migration
        db.session.rollback()
        app.logger.warning("Could not migrate settings keys: %s", exc)


def _sync_user_columns(app):
    """Idempotently add new user profile columns to pre-existing databases."""
    from sqlalchemy import inspect, text

    expected = {
        "job_title": "VARCHAR(120)",
        "department": "VARCHAR(120)",
        "country": "VARCHAR(60)",
    }
    try:
        insp = inspect(db.engine)
        if "users" not in insp.get_table_names():
            return
        existing = {c["name"] for c in insp.get_columns("users")}
        missing = [f"ADD COLUMN {name} {ddl}" for name, ddl in expected.items() if name not in existing]
        if missing:
            db.session.execute(text(f"ALTER TABLE users {', '.join(missing)}"))
            db.session.commit()
            app.logger.info("Added new user profile columns: %s", list(expected))
    except Exception as exc:  # never block boot on a schema sync
        db.session.rollback()
        app.logger.warning("Could not sync users table columns: %s", exc)


def _start_scheduler(app):
    """Hourly brute-force watchdog: >=3 failures/24h on one account → alert."""
    if os.environ.get("INSYRIUM_SKIP_SCHEDULER") == "1":
        return
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true" and app.debug:
        return

    scheduler = BackgroundScheduler(timezone="UTC")

    def watchdog():
        from datetime import datetime, timedelta

        from sqlalchemy import func

        from .models import AuditLog, User

        with app.app_context():
            # AuditLog.created_at is MySQL NOW() (DB-local time); use local now.
            cutoff = datetime.now() - timedelta(hours=24)
            rows = (
                AuditLog.query.with_entities(
                    AuditLog.actor_id,
                    func.count().label("cnt"),
                )
                .filter(
                    AuditLog.action.in_(["login_failed", "otp_failed"]),
                    AuditLog.created_at >= cutoff,
                )
                .group_by(AuditLog.actor_id)
                .having(func.count() >= 3)
                .all()
            )
            for actor_id, count in rows:
                user = User.query.get(actor_id)
                if user is None:
                    continue
                from .services import mail_service

                mail_service.send_alert(
                    f"Possible attack on {user.email}",
                    (
                        f"{count} failed logins / OTP attempts for {user.email} "
                        "in the last 24 hours."
                    ),
                )

    scheduler.add_job(watchdog, "interval", hours=1, id="bruteforce_watchdog")
    scheduler.start()
    app.extensions["scheduler"] = scheduler
