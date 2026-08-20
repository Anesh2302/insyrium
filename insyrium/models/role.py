from ..extensions import db

ROLE_SEED = [
    (1, "user", 0, "Standard authenticated access to the portal products"),
    (2, "admin_support", 1, "Read access to user accounts; handles enquiries"),
    (3, "admin_content", 2, "Publishes and moderates Resources"),
    (4, "admin_platform", 3, "Portal-wide settings, user accounts, content"),
    (5, "supreme_admin", 4, "Full system control. One account in practice"),
]


class Role(db.Model):
    __tablename__ = "roles"

    id = db.Column(db.SmallInteger, primary_key=True)
    name = db.Column(db.String(32), unique=True, nullable=False)
    rank = db.Column(db.SmallInteger, unique=True, nullable=False)
    description = db.Column(db.String(255))

    users = db.relationship("User", back_populates="role")

    @property
    def is_admin(self):
        return self.rank >= 1

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "rank": self.rank,
            "description": self.description,
        }

    @staticmethod
    def seed():
        for rid, name, rank, desc in ROLE_SEED:
            if not db.session.get(Role, rid):
                db.session.add(Role(id=rid, name=name, rank=rank, description=desc))
        db.session.commit()
