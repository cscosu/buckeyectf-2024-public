import sqlalchemy as sa
import sqlalchemy.orm as so
from sqlalchemy.orm import Mapped
from flask_login import UserMixin
from dataclasses import dataclass
from app import db, crypt, login

@dataclass
class User(UserMixin, db.Model):
    id: Mapped[int] = so.mapped_column(primary_key=True)
    username: Mapped[str] = so.mapped_column(sa.String(), index=True, unique=True)
    password: Mapped[str] = so.mapped_column(sa.String())
    score: Mapped[float] = so.mapped_column(sa.Float)

    @staticmethod
    def find(username):
        return db.session.scalar(
            sa.select(User).where(User.username == username)
        )
    def setpw(self,pw):
        self.password = crypt.generate_password_hash(pw).decode()
    def checkpw(self,pw):
        return crypt.check_password_hash(self.password,pw)
    
    def __repr__(self):
        return '<User {u.username} (id {{i.id}})>'.format(u=self).format(i=self)
    
@login.user_loader
def load_user(id):
    return db.session.get(User, int(id))