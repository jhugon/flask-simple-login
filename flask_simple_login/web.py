from typing import TYPE_CHECKING

import flask
from flask import Blueprint
from flask_login import LoginManager, login_required

from .admin import add_admin_commands
from .db import makeDBTable
from .users import (
    User,
    do_login,
    do_logout,
    is_safe_url,
)

if TYPE_CHECKING:
    from flask_sqlalchemy import SQLAlchemy


def setup_auth(app: flask.Flask, db: "SQLAlchemy") -> None:
    "Set configuration keys then run this to setup this blueprint"

    auth = Blueprint("auth", __name__, url_prefix="/auth")

    DBUser = makeDBTable(db)

    login_manager = LoginManager()
    login_manager.login_view = "auth.login"
    login_manager.init_app(app)

    # add Flask CLI Commands
    add_admin_commands(auth, db, DBUser)

    @login_manager.user_loader
    def load_user(user_id) -> User:
        return User(user_id)

    @auth.route("/login", methods=["GET", "POST"])
    def login() -> flask.app.BaseResponse | str:
        nexturl = flask.request.args.get("next")
        if not is_safe_url(nexturl):
            return flask.abort(400)
        return do_login("login.html", nexturl or flask.url_for("index"), db, DBUser)

    @auth.route("/logout", methods=["GET", "POST"])
    @login_required
    def logout() -> flask.app.BaseResponse | str:
        redirect_to = flask.url_for("index")
        return do_logout("logout.html", redirect_to)

    app.register_blueprint(auth)
