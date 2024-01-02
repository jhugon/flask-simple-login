from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.exc import NoResultFound

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

class DBUser(db.Model):
    username: Mapped[str] = mapped_column(primary_key=True)
    passwordhash: Mapped[str]
