import logging
from enum import Enum
from urllib.parse import urljoin, urlparse

import flask
from flask_login import UserMixin, login_user, logout_user
from flask_wtf import FlaskForm
from sqlalchemy.exc import NoResultFound
from werkzeug.security import check_password_hash
from wtforms import PasswordField, StringField
from wtforms.validators import DataRequired

LOGGER = logging.getLogger(__name__)
# from flask.logging import default_handler
# LOGGER.addHandler(default_handler)
# LOGGER.setLevel(logging.DEBUG)


class User(UserMixin):
    def __init__(self, username):
        self.username = username

    def get_id(self):
        return self.username


class LoginForm(FlaskForm):
    username = StringField("username", validators=[DataRequired()])
    password = PasswordField("password", validators=[DataRequired()])


class LogoutForm(FlaskForm):
    pass


class UserInfoEnum(Enum):
    """
    What type of user info store is being used
    """

    USERTEXT = 1
    USERDBTABLE = 2


###########################


def do_login(template_name, redirect_to_on_success, db, DBUser):
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


def do_logout(template_name, redirect_to_on_success):
    form = LogoutForm()
    if form.validate_on_submit():
        logout_user()
        flask.flash("You have been logged out.")
        return flask.redirect(redirect_to_on_success)
    return flask.render_template(template_name, form=form)


def authenticate_user_password(username, password, db, DBUser):
    passwordHash = load_password_hash(username, db, DBUser)
    if passwordHash is not None:
        if check_password_hash(passwordHash, password):
            return True
    return False


def load_password_hash(username, db, DBUser):
    passwordHash = None
    userinfotype = get_user_info_store()
    match userinfotype:
        case UserInfoEnum.USERTEXT:
            fn = flask.current_app.config["LOGIN_USER_FILE_PATH"]
            with open(fn) as userfile:
                for line in userfile:
                    line = line.strip("\n")
                    line_split = line.split(" ")
                    if len(line_split) != 2:
                        continue
                    if line_split[0] == username:
                        passwordHash = line_split[1]
                        break
        case UserInfoEnum.USERDBTABLE:
            try:
                dbuser = db.session.execute(
                    db.select(DBUser).filter_by(username=username)
                ).scalar_one()
            except NoResultFound:
                return None
            else:
                passwordHash = dbuser.passwordhash
        case _:
            raise Exception(f"Unexpected userinfotype: {userinfotype}")
    return passwordHash


###########################


def is_safe_url(target):
    ref_url = urlparse(flask.request.host_url)
    test_url = urlparse(urljoin(flask.request.host_url, target))
    return test_url.scheme in ("http", "https") and ref_url.netloc == test_url.netloc


def get_user_info_store(userinfostorestr=None) -> UserInfoEnum:
    """
    Uses the flask configuration to figure out what type of
    user info store is being used.
    """
    if userinfostorestr is None:
        userinfostorestr = flask.current_app.config["LOGIN_USER_INFO_STORE_TYPE"]
    match userinfostorestr:
        case "textfile":
            return UserInfoEnum.USERTEXT
        case "sqlalchemy":
            return UserInfoEnum.USERDBTABLE
        case _:
            raise Exception(
                "Unexpected value for LOGIN_USER_INFO_STORE_TYPE flask config: "
                f"'{userinfostorestr}'"
            )
