from ..extensions import db
from .role import Role

USER_STATUS = ("pending_verification", "active", "suspended")


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.BigInteger, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(60), nullable=False)  # bcrypt
    role_id = db.Column(db.SmallInteger, db.ForeignKey("roles.id"), nullable=False)
    status = db.Column(
        db.Enum(*USER_STATUS, name="user_status"),
        default="pending_verification",
        nullable=False,
    )
    failed_attempts = db.Column(db.SmallInteger, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)
    organization = db.Column(db.String(160))
    job_title = db.Column(db.String(120))
    department = db.Column(db.String(120))
    country = db.Column(db.String(60))
    created_by = db.Column(db.BigInteger, db.ForeignKey("users.id"), nullable=True)
    last_login_at = db.Column(db.DateTime, nullable=True)
    last_login_ip = db.Column(db.String(45), nullable=True)
    last_login_mac = db.Column(db.String(17), nullable=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(
        db.DateTime, server_default=db.func.now(), onupdate=db.func.now()
    )

    # ── MFA (Section 4.4) ──
    mfa_enabled = db.Column(db.Boolean, default=False, nullable=False)
    phone_number = db.Column(db.String(20), nullable=True)
    phone_verified = db.Column(db.Boolean, default=False, nullable=False)

    role = db.relationship("Role", back_populates="users")
    sessions = db.relationship(
        "Session", back_populates="user", cascade="all, delete-orphan"
    )
    scopes = db.relationship(
        "AdminScope", back_populates="user", cascade="all, delete-orphan"
    )

    @property
    def rank(self):
        return self.role.rank if self.role else -1

    @property
    def role_name(self):
        return self.role.name if self.role else "unknown"

    @property
    def is_supreme(self):
        return self.role_name == "supreme_admin"

    def set_password(self, password):
        import bcrypt

        self.password_hash = bcrypt.hashpw(
            password.encode("utf-8"), bcrypt.gensalt(rounds=12)
        ).decode("utf-8")

    def check_password(self, password):
        import bcrypt

        try:
            return bcrypt.checkpw(
                password.encode("utf-8"), self.password_hash.encode("utf-8")
            )
        except ValueError:
            return False

    def public_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "role": self.role_name,
            "role_id": self.role_id,
            "rank": self.rank,
            "status": self.status,
            "organization": self.organization,
            "job_title": self.job_title,
            "department": self.department,
            "country": self.country,
            "phone_number": self.phone_number,
            "mfa_enabled": self.mfa_enabled,
            "phone_verified": self.phone_verified,
            "last_login_at": self.last_login_at.isoformat()
            if self.last_login_at
            else None,
            "last_login_ip": self.last_login_ip,
            "last_login_mac": self.last_login_mac,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
