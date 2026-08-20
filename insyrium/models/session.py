from ..extensions import db


class Session(db.Model):
    __tablename__ = "sessions"

    id = db.Column(db.BigInteger, primary_key=True)
    user_id = db.Column(
        db.BigInteger, db.ForeignKey("users.id"), nullable=False, index=True
    )
    refresh_token_hash = db.Column(db.String(64), nullable=False)  # sha256 hex
    user_agent = db.Column(db.String(255))
    ip_address = db.Column(db.String(45))
    mac_address = db.Column(db.String(17))
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    expires_at = db.Column(db.DateTime, nullable=False, index=True)

    user = db.relationship("User", back_populates="sessions")
