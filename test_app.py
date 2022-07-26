import flask
from flask import Flask
from flask_talisman import Talisman
from flask_debugtoolbar import DebugToolbarExtension

from flask_simple_login import (
    login_manager,
    auth,
    User,
    login_required,
)

app = Flask(__name__)
# Talisman(app)

app.register_blueprint(auth)
login_manager.init_app(app)

app.debug = True
app.config["SECRET_KEY"] = b"dummy"
app.config["SESSION_PROTECTION"] = "strong"
app.config["LOGIN_USER_FILE_PATH"] = "userfile.txt"

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
