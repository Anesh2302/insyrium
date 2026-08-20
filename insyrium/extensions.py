import os
from flask_socketio import SocketIO
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail

db = SQLAlchemy()
mail = Mail()

async_mode = "eventlet" if os.environ.get("RENDER") or os.environ.get("GUNICORN_WORKER") else "threading"
socketio = SocketIO(cors_allowed_origins="*", async_mode=async_mode)

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],
    storage_uri="memory://",
)
