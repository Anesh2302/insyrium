def log_audit(actor_id, action, target_id=None, metadata=None):
    """Write one row to audit_logs (Section 9.3)."""
    from .extensions import db
    from .models import AuditLog

    db.session.add(
        AuditLog(
            actor_id=actor_id,
            action=action,
            target_id=target_id,
            metadata_=metadata or {},
        )
    )
    db.session.commit()
