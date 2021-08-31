import flask
from flask import Flask
from flask_talisman import Talisman
from flask_debugtoolbar import DebugToolbarExtension

from flask_simple_login import (
    LoginManager,
    User,
    do_login,
    do_logout,
    is_safe_url,
    login_required,
)

app = Flask(__name__)
# Talisman(app)

app.debug = True
app.config["SECRET_KEY"] = b"dummy"
app.config["SESSION_PROTECTION"] = "strong"

login_manager = LoginManager()
login_manager.init_app(app)

toolbar = DebugToolbarExtension(app)


@login_manager.user_loader
def load_user(user_id):
    return User(user_id)


@app.route("/")
@app.route("/index")
@app.route("/index.html")
def index():
    return flask.render_template("index.html")


@app.route("/restricted")
@app.route("/restricted.html")
@login_required
def restricted():
    return flask.render_template("restricted.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    next = flask.request.args.get("next")
    if not is_safe_url(next):
        return flask.abort(400)
    return do_login("login.html", next or flask.url_for("index"))


@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    redirect_to = flask.url_for("index")
    return do_logout("logout.html", redirect_to)
