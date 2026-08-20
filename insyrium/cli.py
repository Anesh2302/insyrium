"""Flask CLI commands: init-db, events, create-superadmin, create-admin."""

import getpass

import click
from flask.cli import with_appcontext

from .extensions import db


def init_app(app):
    app.cli.add_command(init_db)
    app.cli.add_command(create_events)
    app.cli.add_command(create_superadmin)
    app.cli.add_command(create_admin)
    app.cli.add_command(create_user)


@click.command("init-db")
@with_appcontext
def init_db():
    """Create tables and seed roles + settings."""
    from .models import Role, AppSetting

    db.create_all()
    Role.seed()
    for key, value in {
        "portal_name": "Insyrium Portal",
        "allow_registration": "true",
        "maintenance_mode": "false",
        "default_mfa_for_admins": "true",
    }.items():
        if not AppSetting.get(key):
            AppSetting.set(key, value)
    click.echo("✓ Tables created and roles seeded.")


@click.command("create-events")
@with_appcontext
def create_events():
    """Install MySQL EVENT jobs that purge expired sessions/OTP rows (6.7)."""
    sqls = [
        "SET GLOBAL event_scheduler = ON",
        """CREATE EVENT IF NOT EXISTS purge_expired_sessions
           ON SCHEDULE EVERY 1 HOUR
           DO DELETE FROM sessions WHERE expires_at < NOW()""",
        """CREATE EVENT IF NOT EXISTS purge_expired_otp_codes
           ON SCHEDULE EVERY 5 MINUTE
           DO DELETE FROM otp_codes WHERE expires_at < NOW()""",
    ]
    try:
        for sql in sqls:
            db.session.execute(sql)
        db.session.commit()
        click.echo("✓ Cleanup events installed (purge_expired_sessions, purge_expired_otp_codes).")
    except Exception as exc:
        db.session.rollback()
        click.echo(f"✗ Could not create events: {exc}")
        click.echo("  Run as a user with SUPER privileges, or use the APScheduler fallback.")


def _ask(question, default=""):
    value = input(f"{question} [{default}]: ").strip()
    return value or default


@click.command("create-superadmin")
@click.option("--email", default=None)
@click.option("--name", default=None)
@click.option("--password", default=None)
@with_appcontext
def create_superadmin(email, name, password):
    """Create (or update) the Supreme Admin account."""
    from .models import User

    email = email or _ask("Supreme Admin email", "superadmin@insyrium.com")
    name = name or _ask("Full name", "Supreme Admin")
    if not password:
        password = getpass.getpass("Password (min 8, upper+lower+digit): ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            raise click.ClickException("Passwords do not match.")

    user = User.query.filter_by(email=email.lower()).first()
    if user is None:
        user = _mk_user_quiet("supreme_admin", email, name, password, mfa=True)
        click.echo(f"✓ Supreme Admin created: {email}")
    else:
        user.name = name
        user.set_password(password)
        user.status = "active"
        db.session.commit()
        click.echo(f"✓ Supreme Admin updated: {email}")
    click.echo("  OTP codes will appear in the server console until SMTP is configured.")


def _mk_user_quiet(role_name, email, name, password, mfa):
    from .models import Role, User

    role = Role.query.filter_by(name=role_name).first()
    user = User(email=email.lower(), name=name, role_id=role.id,
                status="active", mfa_enabled=mfa)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    try:
        from .services import mail_service
        mail_service.send_welcome_email(user.email, user.name,
                                        role_label=role_name.replace("_", " "))
    except Exception as exc:  # never block account creation on a mail failure
        click.echo(f"  (welcome email not sent: {exc})")
    return user


@click.command("create-admin")
@click.option("--role", default="admin_platform", type=click.Choice(
    ["admin_support", "admin_content", "admin_platform"]))
@click.option("--email", default=None)
@click.option("--name", default=None)
@click.option("--password", default=None)
@with_appcontext
def create_admin(role, email, name, password):
    """Create a Support / Content / Platform admin (MFA on by default)."""
    email = email or _ask("Admin email", f"admin@{role.split('_', 1)[-1]}.com")
    name = name or _ask("Full name", "Portal Admin")
    if not password:
        password = getpass.getpass("Password (min 8, upper+lower+digit): ")
    user = _mk_user_quiet(role, email, name, password, mfa=True)
    click.echo(f"✓ {role} created: {email}")


@click.command("create-user")
@click.option("--email", default=None)
@click.option("--name", default=None)
@click.option("--password", default=None)
@with_appcontext
def create_user(email, name, password):
    """Create a regular user account (no MFA by default)."""
    email = email or _ask("User email", "user@example.com")
    name = name or _ask("Full name", "Portal User")
    if not password:
        password = getpass.getpass("Password (min 8, upper+lower+digit): ")
    user = _mk_user_quiet("user", email, name, password, mfa=False)
    click.echo(f"✓ user created: {email} (status=active)")
