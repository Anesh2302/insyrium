"""Admin-facing documentation: every meaningful community/security event is
written to human-readable doc files under the project's docs/ folder so
administrators have a durable, auditable record (CSV + JSONL + summary).

Portability note: on serverless platforms (Vercel/Lambda) the filesystem is
read-only, so the database (``community_events``) is the authoritative store and
the docs/ files are a best-effort mirror. File failures never break a request.
"""

import csv
import io
import json
import logging
import os
from datetime import datetime, timedelta

from flask import request

from ..audit import log_audit

log = logging.getLogger(__name__)

DOCS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "docs")
EVENTS_DIR = os.path.join(DOCS_DIR, "community", "events")
DAILY_REPORT_DIR = os.path.join(DOCS_DIR, "community", "reports")


def _ensure_dirs():
    """Best effort -- returns True when the docs tree is writable."""
    try:
        os.makedirs(EVENTS_DIR, exist_ok=True)
        os.makedirs(DAILY_REPORT_DIR, exist_ok=True)
        return True
    except OSError:
        return False


def _today():
    return datetime.utcnow().strftime("%Y-%m-%d")


def write_event(kind, data, actor_id=None):
    """Record a community event durably in the DB, then mirror to docs/ if possible.

    Returns the docs path when the mirror was written, otherwise None. Never raises:
    event logging must not be able to fail the caller's request.
    """
    data = dict(data or {})
    event = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "event": kind,
        "ip": request.remote_addr or "",
        **data,
    }

    # ── durable store (database) ──────────────────────────────────────
    try:
        from ..extensions import db
        from ..models import CommunityEvent

        row = CommunityEvent(
            kind=kind,
            actor_id=actor_id,
            server_id=data.get("server_id"),
            target_id=data.get("target_id"),
            ip=request.remote_addr or "",
            payload=data,
        )
        db.session.add(row)
        db.session.commit()
    except Exception:
        try:
            from ..extensions import db

            db.session.rollback()
        except Exception:
            pass
        log.warning("Could not persist community event %s", kind, exc_info=True)

    # ── human-readable mirror (best effort) ───────────────────────────
    path = None
    try:
        if _ensure_dirs():
            path = os.path.join(EVENTS_DIR, f"events_{_today()}.jsonl")
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(event, default=str) + "\n")
    except OSError:
        # Read-only filesystem (serverless) -- the DB row above is the record.
        path = None

    if actor_id is not None:
        try:
            log_audit(actor_id, f"community_{kind}", metadata=data)
        except Exception:
            pass
    return path


def _events_from_db(days):
    from ..extensions import db
    from ..models import CommunityEvent

    since = datetime.utcnow() - timedelta(days=days)
    rows = (
        CommunityEvent.query.filter(CommunityEvent.created_at >= since)
        .order_by(CommunityEvent.id.asc())
        .all()
    )
    return [r.to_dict() for r in rows]


def daily_summary():
    """Collate today's events into a CSV report.

    Returns ``(csv_path_or_None, rows)``. The path is None when the docs tree is
    not writable (serverless) -- callers should use ``csv_bytes`` instead.
    """
    rows = list_events(1)
    buf = io.StringIO()
    fieldnames = ["ts", "event", "actor_id", "target", "details", "ip"]
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow(
            {
                "ts": row.get("ts", ""),
                "event": row.get("event", ""),
                "actor_id": row.get("actor_id", ""),
                "target": row.get("target_id", row.get("target", "")),
                "details": json.dumps(
                    {k: v for k, v in row.items() if k not in fieldnames},
                    default=str,
                ),
                "ip": row.get("ip", ""),
            }
        )

    csv_path = None
    try:
        if _ensure_dirs():
            csv_path = os.path.join(DAILY_REPORT_DIR, f"community_report_{_today()}.csv")
            with open(csv_path, "w", newline="", encoding="utf-8") as fh:
                fh.write(buf.getvalue())
    except OSError:
        csv_path = None

    return csv_path, rows


def csv_bytes(days=1):
    """Render the daily CSV in memory -- works even when the FS is read-only."""
    _path, rows = daily_summary()
    buf = io.StringIO()
    fieldnames = ["ts", "event", "actor_id", "target", "details", "ip"]
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow(
            {
                "ts": row.get("ts", ""),
                "event": row.get("event", ""),
                "actor_id": row.get("actor_id", ""),
                "target": row.get("target_id", row.get("target", "")),
                "details": json.dumps(
                    {k: v for k, v in row.items() if k not in fieldnames},
                    default=str,
                ),
                "ip": row.get("ip", ""),
            }
        )
    return buf.getvalue().encode("utf-8")


def list_events(days=7):
    """Return events from the last N days, newest last."""
    days = max(1, min(int(days), 30))
    try:
        return _events_from_db(days)
    except Exception:
        log.warning("Falling back to docs/ event files", exc_info=True)
        return _list_events_from_files(days)


def _list_events_from_files(days):
    out = []
    for offset in range(days):
        day = (datetime.utcnow() - timedelta(days=offset)).strftime("%Y-%m-%d")
        path = os.path.join(EVENTS_DIR, f"events_{day}.jsonl")
        try:
            if not os.path.exists(path):
                continue
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        try:
                            out.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
        except OSError:
            break
    return out