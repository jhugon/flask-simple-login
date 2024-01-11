import flask
from flask import Blueprint

from .admin import add_admin_commands
from .db import makeDBTable
from .users import (
    LoginManager,
    User,
    UserInfoEnum,
    do_login,
    do_logout,
    get_user_info_store,
    is_safe_url,
    login_required,
)


def setup_auth(app, db=None):
    "Set configuration keys then run this to setup this blueprint"

    auth = Blueprint("auth", __name__, url_prefix="/auth")

    DBUser = None
    match get_user_info_store(app.config["LOGIN_USER_INFO_STORE_TYPE"]):
        case UserInfoEnum.USERDBTABLE:
            if db is None:
                raise Exception(f"db {db} is none when config is set to SQLAlchemy")
            DBUser = makeDBTable(db)
        case _:
            pass

    login_manager = LoginManager()
    login_manager.login_view = "auth.login"
    login_manager.init_app(app)

    # add Flask CLI Commands
    add_admin_commands(auth, db, DBUser)

    @login_manager.user_loader
    def load_user(user_id):
        return User(user_id)

    @auth.route("/login", methods=["GET", "POST"])
    def login():
        nexturl = flask.request.args.get("next")
        if not is_safe_url(nexturl):
            return flask.abort(400)
        return do_login("login.html", nexturl or flask.url_for("index"), db, DBUser)

    @auth.route("/logout", methods=["GET", "POST"])
    @login_required
    def logout():
        redirect_to = flask.url_for("index")
        return do_logout("logout.html", redirect_to)

    app.register_blueprint(auth)
