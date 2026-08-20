import os, sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.chdir(os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("INSYRIUM_SKIP_SCHEDULER", "1")
os.environ.setdefault("FLASK_DEBUG", "0")

db_url = os.environ.get("DATABASE_URL", "")
if not db_url or "localhost" in db_url or "127.0.0.1" in db_url:
    os.environ["DATABASE_URL"] = "sqlite:////tmp/insyrium.db"

from app import app as application
