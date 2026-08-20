from flask_socketio import SocketIO
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail

db = SQLAlchemy()
mail = Mail()

# Threading async mode (no eventlet monkey-patching) — works with the Werkzeug
# dev server via simple-websocket and keeps pymysql/APScheduler happy.
socketio = SocketIO(cors_allowed_origins="*", async_mode="threading")

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],
    storage_uri="memory://",
)
