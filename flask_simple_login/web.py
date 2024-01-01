import flask
from flask import Blueprint

from .users import User, do_login, do_logout, is_safe_url, login_required, LoginManager
from .admin import add_admin_commands

auth = Blueprint("auth", __name__, url_prefix="/auth")

login_manager = LoginManager()
login_manager.login_view = "auth.login"

def setup_auth(app):
    "Set configuration keys then run this to setup this blueprint"
    app.register_blueprint(auth)
    login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User(user_id)


@auth.route("/login", methods=["GET", "POST"])
def login():
    next = flask.request.args.get("next")
    if not is_safe_url(next):
        return flask.abort(400)
    return do_login("login.html", next or flask.url_for("index"))


@auth.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    redirect_to = flask.url_for("index")
    return do_logout("logout.html", redirect_to)


##### Flask CLI Commands

add_admin_commands(auth)
