import getpass
import string
import sys
from typing import TYPE_CHECKING

import click
import flask
from sqlalchemy.exc import NoResultFound
from werkzeug.security import generate_password_hash

if TYPE_CHECKING:
    from flask_sqlalchemy import SQLAlchemy


def add_admin_commands(auth: flask.Blueprint, db: "SQLAlchemy", DBUser) -> None:
    "add admin commands to blueprint 'auth'"

    @auth.cli.command("initdb", help="initialize database login user table")
    def initdb() -> None:
        db.create_all()
        print("User database table created!")

    @auth.cli.command(
        "adduser",
        help="Adds user to the current app's user storage. Will ask for password",
    )
    @click.argument("username")
    def adduser(username: str) -> None:
        app = flask.current_app
        with app.app_context():
            adduserdb(app, username)
        print("Successfully added new user")

    @auth.cli.command(
        "deleteuser", help="Deletes user from the current app's user storage."
    )
    @click.argument("username")
    def deleteuser(username: str) -> None:
        app = flask.current_app
        with app.app_context():
            try:
                dbuser = db.session.execute(
                    db.select(DBUser).filter_by(username=username)
                ).scalar_one()
            except NoResultFound:
                print("Error: username not found. Exiting.", file=sys.stderr)
                sys.exit(1)
            else:
                db.session.delete(dbuser)
                db.session.commit()
        print("Successfully deleted user")

    @auth.cli.command("changeuserpassword", help="Change a user's password.")
    @click.argument("username")
    def changeuserpassword(username: str) -> None:
        app = flask.current_app
        with app.app_context():
            try:
                dbuser = db.session.execute(
                    db.select(DBUser).filter_by(username=username)
                ).scalar_one()
            except NoResultFound:
                print("Error: username not found. Exiting.", file=sys.stderr)
                sys.exit(1)
            else:
                print("NEW PASSWORD:")
                dbuser.passwordhash = promptvalidateandhashpassword()
                db.session.commit()
        print("Successfully updated password")

    @auth.cli.command("listusers", help="List all users.")
    def listusers() -> None:
        app = flask.current_app
        with app.app_context():
            users = db.session.execute(db.select(DBUser)).scalars()
            for user in users:
                print(user.username)

    def adduserdb(app: flask.Flask, username: str) -> None:
        with app.app_context():
            validateusername(username)
            passwordhash = promptvalidateandhashpassword()
            dbuser = DBUser(username=username, passwordhash=passwordhash)
            db.session.add(dbuser)
            db.session.commit()


def validateusername(username: str) -> None:
    minlen = 3
    maxlen = 30
    if len(username) < minlen or len(username) > maxlen:
        raise Exception(
            f'Error: username "{username}" should be between'
            " {minlen} and {maxlen} characters long."
        )
    for x in username:
        if x in string.whitespace or x not in string.printable:
            raise Exception(
                f'Error: username "{username}" contains a space'
                " or non-printable characters. This is not allowed."
            )


def validatepassword(password: str) -> None:
    minlen = 8
    maxlen = 30
    if len(password) < minlen or len(password) > maxlen:
        raise Exception(
            "Error: password should be between {minlen} and {maxlen} characters long."
        )
    for x in password:
        if x in string.whitespace or x not in string.printable:
            raise Exception(
                "Error: password contains a space"
                " or non-printable characters. This is not allowed."
            )


def hashpassword(password: str) -> str:
    passwordHash = generate_password_hash(
        password, "pbkdf2:sha256:100000", salt_length=16
    )
    for x in passwordHash:
        if x in string.whitespace or x not in string.printable:
            raise Exception(
                "Error: passwordHash contains a space or "
                "non-printable characters. This is not allowed. Try again, "
                "a different salt may help."
            )
    return passwordHash


def promptvalidateandhashpassword() -> str:
    password = getpass.getpass("Enter password: ")
    password2 = getpass.getpass("Re-enter password: ")
    if password != password2:
        print("Error: passwords don't match! Exiting.", file=sys.stderr)
        sys.exit(1)
    validatepassword(password)
    return hashpassword(password)
