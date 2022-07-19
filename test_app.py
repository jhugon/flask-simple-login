import flask
from flask import Flask
from flask_talisman import Talisman
from flask_debugtoolbar import DebugToolbarExtension

from flask_simple_login import (
    LoginManager,
    User,
    login_required,
    auth,
)

app = Flask(__name__)
# Talisman(app)

app.register_blueprint(auth)
login_manager = LoginManager()
login_manager.init_app(app)
@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

app.debug = True
app.config["SECRET_KEY"] = b"dummy"
app.config["SESSION_PROTECTION"] = "strong"

toolbar = DebugToolbarExtension(app)


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
