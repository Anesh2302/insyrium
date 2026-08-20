from ..extensions import db


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.BigInteger, primary_key=True)
    actor_id = db.Column(db.BigInteger, db.ForeignKey("users.id"), nullable=False)
    action = db.Column(db.String(64), nullable=False, index=True)
    target_id = db.Column(db.BigInteger, nullable=True)
    metadata_ = db.Column("metadata", db.JSON, nullable=True)
    created_at = db.Column(
        db.DateTime, server_default=db.func.now(), index=True
    )

    def to_dict(self):
        return {
            "id": self.id,
            "actor_id": self.actor_id,
            "action": self.action,
            "target_id": self.target_id,
            "metadata": self.metadata_,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
