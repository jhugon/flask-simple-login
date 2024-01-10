import flask
from flask import Flask
from flask_debugtoolbar import DebugToolbarExtension
from flask_sqlalchemy import SQLAlchemy
# from flask_talisman import Talisman

from flask_simple_login import (
    setup_auth,
    login_required,
)

app = Flask(__name__)
# Talisman(app)

app.debug = True
app.config["SECRET_KEY"] = b"dummy"
app.config["SESSION_PROTECTION"] = "strong"

### Test with text file
# app.config["LOGIN_USER_INFO_STORE_TYPE"] = "textfile"
# app.config["LOGIN_USER_FILE_PATH"] = "userfile.txt"
# db = None

## Test with SQLite db
app.config["LOGIN_USER_INFO_STORE_TYPE"] = "sqlalchemy"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///project.db"
db = SQLAlchemy()
db.init_app(app)

setup_auth(app, db)

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
