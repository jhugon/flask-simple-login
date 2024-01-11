import flask
from flask import Flask
from flask_debugtoolbar import DebugToolbarExtension
from flask_sqlalchemy import SQLAlchemy

# from flask_talisman import Talisman
from flask_simple_login import (
    login_required,
    setup_auth,
)

app = Flask(__name__)
# Talisman(app)

app.debug = True
app.config["SECRET_KEY"] = b"dummy"
app.config["SESSION_PROTECTION"] = "strong"

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///project.db"
db = SQLAlchemy()
db.init_app(app)

setup_auth(app, db)

toolbar = DebugToolbarExtension(app)


@app.route("/")
@app.route("/index")
@app.route("/index.html")
def index() -> flask.BaseResponse:
    return flask.render_template("index.html")


@app.route("/restricted")
@app.route("/restricted.html")
@login_required
def restricted() -> flask.BaseResponse:
    return flask.render_template("restricted.html")
