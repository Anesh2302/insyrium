from ..extensions import db


class AppSetting(db.Model):
    __tablename__ = "app_settings"

    id = db.Column(db.BigInteger, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False)
    value = db.Column(db.String(500), nullable=False, default="")
    updated_by = db.Column(db.BigInteger, db.ForeignKey("users.id"), nullable=True)
    updated_at = db.Column(
        db.DateTime, server_default=db.func.now(), onupdate=db.func.now()
    )

    @staticmethod
    def get(key, default=None):
        row = db.session.query(AppSetting).filter_by(key=key).first()
        return row.value if row else default

    @staticmethod
    def set(key, value, updated_by=None):
        row = db.session.query(AppSetting).filter_by(key=key).first()
        if row is None:
            row = AppSetting(key=key, value=str(value))
            db.session.add(row)
        row.value = str(value)
        row.updated_by = updated_by
        db.session.commit()
        return row
