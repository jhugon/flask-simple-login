from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import Mapped, mapped_column


def makeDBTable(db: SQLAlchemy):
    class DBUser(db.Model):  # type:ignore
        username: Mapped[str] = mapped_column(primary_key=True)
        passwordhash: Mapped[str]

    return DBUser
