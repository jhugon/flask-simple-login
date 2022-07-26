import flask
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired
from urllib.parse import urlparse, urljoin
from werkzeug.security import generate_password_hash, check_password_hash
import os
import string


def do_login(template_name, redirect_to_on_success):
    form = LoginForm()
    if form.validate_on_submit():
        # Login and validate the user.
        # user should be an instance of your `User` class
        username = form.username.data
        password = form.password.data
        print(f"User tried to login with: {username}, {password}")
        if not User.authenticate_user_password(username, password):
            print("Login failed")
            flask.flash("Incorrect username and/or password.")
            return flask.redirect(flask.url_for("auth.login"))
        user = User(username)
        login_user(user)

        print("Login success")
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


class User(UserMixin):
    @staticmethod
    def load_password_hash(username):
        passwordHash = None
        fn = flask.current_app.config["LOGIN_USER_FILE_PATH"]
        with open(fn) as userfile:
            for line in userfile:
                line = line.strip("\n")
                line_split = line.split(" ")
                print(line_split)
                if len(line_split) != 2:
                    continue
                if line_split[0] == username:
                    passwordHash = line_split[1]
                    break
        return passwordHash

    def authenticate_user_password(username, password):
        passwordHash = User.load_password_hash(username)
        if not (passwordHash is None):
            if check_password_hash(passwordHash, password):
                return True
        else:
            return False

    def __init__(self, username):
        self.username = username

    def get_id(self):
        return self.username


class LoginForm(FlaskForm):
    username = StringField("username", validators=[DataRequired()])
    password = PasswordField("password", validators=[DataRequired()])


class LogoutForm(FlaskForm):
    pass


def is_safe_url(target):
    ref_url = urlparse(flask.request.host_url)
    test_url = urlparse(urljoin(flask.request.host_url, target))
    return test_url.scheme in ("http", "https") and ref_url.netloc == test_url.netloc


def gen_random_bytes():
    return os.urandom(24)


def make_user_file_line(username, password):
    """
    The user file line is of the form: "<username> <password hash>"
    No spaces or control characters are allowed in the username or password hash

    The user file only lists these lines
    """
    if len(username) < 3 or len(username) > 30:
        raise Exception(
            f'Error: username "{username}" should be between 3 and 30 characters long.'
        )
    if len(password) < 3 or len(password) > 30:
        raise Exception(f"Error: password should be between 8 and 30 characters long.")
    for x in username:
        if x in string.whitespace or not (x in string.printable):
            raise Exception(
                f'Error: username "{username}" contains a space or non-printable characters. This is not allowed.'
            )
    result = username + " "
    passwordHash = generate_password_hash(
        password, "pbkdf2:sha256:100000", salt_length=16
    )
    for x in passwordHash:
        if x in string.whitespace or not (x in string.printable):
            raise Exception(
                f'Error: passwordHash "{username}" contains a space or non-printable characters. This is not allowed.'
            )
    result += passwordHash
    return result


def print_user_file_line_command():
    import argparse
    import getpass
    import sys

    tempOut = sys.stdout
    sys.stdout = sys.stderr

    parser = argparse.ArgumentParser(
        description="Asks for a username and password (entered 2 times to check for consistency) and generates a line suitable for the user file"
    )
    args = parser.parse_args()

    username = input("Enter username: ")
    password1 = getpass.getpass("Enter password: ")
    password2 = getpass.getpass("Re-enter password: ")
    if password1 != password2:
        print("Passwords don't match!")
        return
    line = make_user_file_line(username, password1)
    sys.stdout = tempOut
    print(line)
