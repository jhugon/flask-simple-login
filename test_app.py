import flask
from flask import Flask
from flask_talisman import Talisman
from flask_debugtoolbar import DebugToolbarExtension

from flask_simple_login import (
    setup_auth,
    login_required,
)

app = Flask(__name__)
# Talisman(app)

app.debug = True
app.config["SECRET_KEY"] = b"dummy"
app.config["SESSION_PROTECTION"] = "strong"

app.config["LOGIN_USER_INFO_STORE_TYPE"] = "textfile"
app.config["LOGIN_USER_FILE_PATH"] = "userfile.txt"
#app.config["LOGIN_USER_INFO_STORE_TYPE"] = "sqlalchemy"

setup_auth(app)

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
