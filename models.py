from datetime import date
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()


class User(db.Model, UserMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    expire_date = db.Column(db.Date, nullable=False)
    is_active_flag = db.Column(db.Boolean, default=True)
    is_admin_flag = db.Column(db.Boolean, default=False)  # <– cờ admin

    def is_active(self):
        """Flask-Login dùng hàm này để kiểm tra user có còn hoạt động không."""
        return self.is_active_flag and (self.expire_date >= date.today())

    def is_admin(self):
        return bool(self.is_admin_flag)

    def __repr__(self):
        return f"<User {self.username} (expire: {self.expire_date})>"
