from ..extensions import db

CONTENT_STATUS = ("draft", "pending_review", "published", "rejected")
CONTENT_TYPES = (
    "article",
    "framework",
    "template",
    "knowledge_center",
    "research",
    "video",
    "download",
)


class ContentResource(db.Model):
    __tablename__ = "content_resources"

    id = db.Column(db.BigInteger, primary_key=True)
    type = db.Column(db.Enum(*CONTENT_TYPES, name="content_type"), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text, nullable=False)
    status = db.Column(
        db.Enum(*CONTENT_STATUS, name="content_status"),
        default="draft",
        nullable=False,
    )
    file_url = db.Column(db.String(500))
    product = db.Column(db.Enum(*("insyrium", "sape_tqm", "decisium", "mirads_builder"), name="content_product"), default="insyrium", nullable=False)
    author_id = db.Column(
        db.BigInteger, db.ForeignKey("users.id"), nullable=False, index=True
    )
    moderator_id = db.Column(db.BigInteger, db.ForeignKey("users.id"), nullable=True)
    published_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(
        db.DateTime, server_default=db.func.now(), onupdate=db.func.now()
    )

    author = db.relationship("User", foreign_keys=[author_id])
    moderator = db.relationship("User", foreign_keys=[moderator_id])

    def to_dict(self):
        return {
            "id": self.id,
            "type": self.type,
            "title": self.title,
            "body": self.body,
            "status": self.status,
            "file_url": self.file_url,
            "product": self.product,
            "author": self.author.name if self.author else None,
            "author_id": self.author_id,
            "moderator": self.moderator.name if self.moderator else None,
            "published_at": self.published_at.isoformat()
            if self.published_at
            else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
