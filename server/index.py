import os, sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.chdir(os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("INSYRIUM_SKIP_SCHEDULER", "1")
os.environ.setdefault("FLASK_DEBUG", "0")

db_url = os.environ.get("DATABASE_URL", "")
if not db_url or "localhost" in db_url or "127.0.0.1" in db_url:
    os.environ["DATABASE_URL"] = "sqlite:////tmp/insyrium.db"

from app import app as application

with application.app_context():
    from insyrium.extensions import db
    from insyrium.models import User, Role
    if not User.query.first():
        roles = {}
        for name, level in [("user",0),("admin_support",1),("admin_content",2),("admin_platform",3),("supreme_admin",4)]:
            r = Role.query.filter_by(name=name).first()
            if not r:
                r = Role(name=name, level=level, permissions=0)
                db.session.add(r)
                db.session.flush()
            roles[name] = r
        db.session.commit()

        accounts = [
            ("simonpetercys@gmail.com", "Simon Peter", "supreme_admin", "Simon#23!tech"),
            ("platform@insyrium.com", "Platform Admin", "admin_platform", "Simon#23!tech"),
            ("content@insyrium.com", "Content Manager", "admin_content", "Simon#23!tech"),
            ("support@insyrium.com", "Support Lead", "admin_support", "Simon#23!tech"),
            ("abisrmvec@gmail.com", "Abi", "user", "Simon#23!tech"),
            ("claraelizbeth086@gmail.com", "Clara Elizabeth", "user", "Simon#23!tech"),
        ]
        for email, name, role_name, pw in accounts:
            u = User(email=email, name=name, role_id=roles[role_name].id, mfa_enabled=True)
            u.set_password(pw)
            db.session.add(u)
        db.session.commit()
