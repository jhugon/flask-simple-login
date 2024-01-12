import logging
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlparse

import flask
from flask_login import UserMixin, login_user, logout_user
from flask_wtf import FlaskForm
from sqlalchemy.exc import NoResultFound
from werkzeug.security import check_password_hash
from wtforms import PasswordField, StringField
from wtforms.validators import DataRequired

if TYPE_CHECKING:
    from flask_sqlalchemy import SQLAlchemy


LOGGER = logging.getLogger(__name__)
# from flask.logging import default_handler
# LOGGER.addHandler(default_handler)
# LOGGER.setLevel(logging.DEBUG)


class User(UserMixin):
    def __init__(self, username: str):
        self.username = username

    def get_id(self) -> str:
        return self.username


class LoginForm(FlaskForm):
    username = StringField("username", validators=[DataRequired()])
    password = PasswordField("password", validators=[DataRequired()])


class LogoutForm(FlaskForm):
    pass


###########################


def do_login(
    template_name: str, redirect_to_on_success: str, db: "SQLAlchemy", DBUser
) -> flask.app.BaseResponse | str:
    form = LoginForm()
    if form.validate_on_submit():
        # Login and validate the user.
        # user should be an instance of your `User` class
        username = form.username.data
        password = form.password.data
        if not authenticate_user_password(username, password, db, DBUser):
            LOGGER.info(f"Login failed for username: '{username}'")
            flask.flash("Incorrect username and/or password.")
            return flask.redirect(flask.url_for("auth.login"))
        user = User(username)
        ## This is more of a persist login sessions setting
        remember = False
        try:
            remember = flask.current_app.config["LOGIN_REMEMBER"]
        except KeyError:
            pass
        login_user(user, remember=remember)

        LOGGER.info(f"Login success for username: '{username}'")
        flask.flash("Logged in successfully.")

        return flask.redirect(redirect_to_on_success)
    return flask.render_template(template_name, form=form)


def do_logout(
    template_name: str, redirect_to_on_success: str
) -> flask.app.BaseResponse | str:
    form = LogoutForm()
    if form.validate_on_submit():
        logout_user()
        flask.flash("You have been logged out.")
        return flask.redirect(redirect_to_on_success)
    return flask.render_template(template_name, form=form)


def authenticate_user_password(
    username: str, password: str, db: "SQLAlchemy", DBUser
) -> bool:
    passwordHash = load_password_hash(username, db, DBUser)
    if passwordHash is not None:
        if check_password_hash(passwordHash, password):
            return True
    return False


def load_password_hash(username: str, db: "SQLAlchemy", DBUser) -> str | None:
    try:
        dbuser = db.session.execute(
            db.select(DBUser).filter_by(username=username)
        ).scalar_one()
    except NoResultFound:
        return None
    else:
        return dbuser.passwordhash


###########################


def is_safe_url(target: str | None) -> bool:
    if target is None:  # None is safe and will be redirected
        return True
    ref_url = urlparse(flask.request.host_url)
    test_url = urlparse(urljoin(flask.request.host_url, target))
    return test_url.scheme in ("http", "https") and ref_url.netloc == test_url.netloc
