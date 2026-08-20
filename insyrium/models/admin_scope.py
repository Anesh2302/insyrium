from ..extensions import db

PRODUCTS = ("insyrium", "sape_tqm", "decisium", "mirads_builder")


class AdminScope(db.Model):
    __tablename__ = "admin_scopes"

    id = db.Column(db.BigInteger, primary_key=True)
    user_id = db.Column(db.BigInteger, db.ForeignKey("users.id"), nullable=False)
    product = db.Column(
        db.Enum(*PRODUCTS, name="product"),
        nullable=False,
    )

    user = db.relationship("User", back_populates="scopes")

    __table_args__ = (db.UniqueConstraint("user_id", "product"),)
