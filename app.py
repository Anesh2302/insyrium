"""Insyrium Portal — entry point.

Run with:  python app.py
"""

import os

from insyrium import create_app, socketio

app = create_app()

if __name__ == "__main__":
    socketio.run(
        app,
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "5000")),
        debug=os.getenv("FLASK_DEBUG", "1") == "1",
        use_reloader=False,
    )
