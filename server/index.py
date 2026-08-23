import os, sys, logging

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.chdir(os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("INSYRIUM_SKIP_SCHEDULER", "1")
os.environ.setdefault("FLASK_DEBUG", "0")

db_url = os.environ.get("DATABASE_URL", "")
if not db_url or "localhost" in db_url or "127.0.0.1" in db_url:
    os.environ["DATABASE_URL"] = "sqlite:////tmp/insyrium.db"

from app import app as application

_log = logging.getLogger("vercel.seed")

_DEFAULT_PASSWORD = os.environ.get("SEED_PASSWORD", "Simon#23!tech")

def _seed():
    try:
        from insyrium.extensions import db
        from insyrium.models import User, Role
        if User.query.first():
            return
        roles = {}
        for name, rank in [("user", 0), ("admin_support", 1), ("admin_content", 2),
                           ("admin_platform", 3), ("supreme_admin", 4)]:
            r = Role.query.filter_by(name=name).first()
            if not r:
                r = Role(name=name, rank=rank, description=name.replace("_", " ").title())
                db.session.add(r)
                db.session.flush()
            roles[name] = r
        db.session.commit()

        for email, name, role_name in [
            ("simonpetercys@gmail.com", "Simon Peter", "supreme_admin"),
            ("platform@insyrium.com", "Platform Admin", "admin_platform"),
            ("content@insyrium.com", "Content Manager", "admin_content"),
            ("support@insyrium.com", "Support Lead", "admin_support"),
            ("abisrmvec@gmail.com", "Abi", "user"),
            ("claraelizbeth086@gmail.com", "Clara Elizabeth", "user"),
        ]:
            if not User.query.filter_by(email=email).first():
                u = User(email=email, name=name, role_id=roles[role_name].id, mfa_enabled=True)
                u.set_password(_DEFAULT_PASSWORD)
                db.session.add(u)
        db.session.commit()
        _log.info("Seeded %d users", User.query.count())
    except Exception as exc:
        _log.error("Seed failed: %s", exc, exc_info=True)
        try:
            from insyrium.extensions import db as _db
            _db.session.rollback()
        except Exception:
            pass

with application.app_context():
    _seed()
