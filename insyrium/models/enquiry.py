from ..extensions import db

ENQUIRY_STATUS = ("new", "open", "responded", "closed")


class Enquiry(db.Model):
    __tablename__ = "enquiries"

    id = db.Column(db.BigInteger, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    subject = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    status = db.Column(
        db.Enum(*ENQUIRY_STATUS, name="enquiry_status"), default="new", nullable=False
    )
    handled_by = db.Column(db.BigInteger, db.ForeignKey("users.id"), nullable=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    handler = db.relationship("User", foreign_keys=[handled_by])

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "subject": self.subject,
            "message": self.message,
            "status": self.status,
            "handled_by": self.handler.name if self.handler else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
