from ..extensions import db


class OtpCode(db.Model):
    __tablename__ = "otp_codes"

    id = db.Column(db.BigInteger, primary_key=True)
    user_id = db.Column(
        db.BigInteger, db.ForeignKey("users.id"), nullable=False, index=True
    )
    code_hash = db.Column(db.String(64), nullable=False)  # sha256 hex digest
    purpose = db.Column(
        db.Enum("login", "step_up", name="otp_purpose"), nullable=False
    )
    channel = db.Column(db.Enum("email", "sms", name="otp_channel"), nullable=False)
    attempts = db.Column(db.SmallInteger, default=0, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    expires_at = db.Column(db.DateTime, nullable=False, index=True)

    user = db.relationship("User")
