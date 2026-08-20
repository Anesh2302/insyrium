"""Admin-facing documentation: every meaningful community/security event is
written to human-readable doc files under the project's docs/ folder so
administrators have a durable, auditable record (CSV + JSONL + summary)."""

import csv
import json
import os
from datetime import datetime

from flask import request

from ..audit import log_audit

DOCS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "docs")
EVENTS_DIR = os.path.join(DOCS_DIR, "community", "events")
DAILY_REPORT_DIR = os.path.join(DOCS_DIR, "community", "reports")


def _ensure_dirs():
    os.makedirs(EVENTS_DIR, exist_ok=True)
    os.makedirs(DAILY_REPORT_DIR, exist_ok=True)


def _today():
    return datetime.utcnow().strftime("%Y-%m-%d")


def write_event(kind, data, actor_id=None):
    """Append a JSONL row to today's community events doc + mirror to audit_logs."""
    _ensure_dirs()
    event = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "event": kind,
        "ip": request.remote_addr or "",
        **data,
    }
    path = os.path.join(EVENTS_DIR, f"events_{_today()}.jsonl")
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(event) + "\n")

    if actor_id is not None:
        try:
            log_audit(actor_id, f"community_{kind}", metadata=data)
        except Exception:
            pass
    return path


def daily_summary():
    """Collate today's events into a CSV report doc and return its path."""
    _ensure_dirs()
    path = os.path.join(EVENTS_DIR, f"events_{_today()}.jsonl")
    rows = []
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    csv_path = os.path.join(DAILY_REPORT_DIR, f"community_report_{_today()}.csv")
    fieldnames = ["ts", "event", "actor_id", "target", "details", "ip"]
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    "ts": row.get("ts", ""),
                    "event": row.get("event", ""),
                    "actor_id": row.get("actor_id", ""),
                    "target": row.get("target", ""),
                    "details": json.dumps(
                        {k: v for k, v in row.items() if k not in fieldnames}
                    ),
                    "ip": row.get("ip", ""),
                }
            )
    return csv_path, len(rows)


def list_events(days=7):
    """Return events from the last N days as a list of dicts."""
    _ensure_dirs()
    out = []
    from datetime import date, timedelta

    today = date.today()
    for offset in range(days):
        day = (today - timedelta(days=offset)).strftime("%Y-%m-%d")
        path = os.path.join(EVENTS_DIR, f"events_{day}.jsonl")
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
    return out
