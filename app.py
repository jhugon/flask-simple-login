import flask
from flask import Flask
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired
from flask_debugtoolbar import DebugToolbarExtension
from urllib.parse import urlparse, urljoin

from werkzeug.security import generate_password_hash, check_password_hash
import os
import string

app = Flask(__name__)

app.debug = True
app.config["SECRET_KEY"] = b"dummy"

login_manager = LoginManager()
login_manager.init_app(app)

toolbar = DebugToolbarExtension(app)


class User(UserMixin):
    @staticmethod
    def load_password_hash(username):
        passwordHash = None
        with open("userfile.txt") as userfile:
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


@login_manager.user_loader
def load_user(user_id):
    return User(user_id)


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
    if len(password) < 8 or len(password) > 30:
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
    result += passwordHash + "\n"
    return result


@app.route("/")
@app.route("/index")
@app.route("/index.html")
def hello_world():
    return "<html>\n<head></head>\n<body>\n<p>Hello, World!</p>\n</body>\n</html>"


@app.route("/restricted")
@app.route("/restricted.html")
@login_required
def restricted():
    return "<html>\n<head></head>\n<body>\n<p>This page is restricted. You should only see it if you are logged in.</p>\n</body>\n</html>"


@app.route("/login", methods=["GET", "POST"])
def login():
    # Here we use a class of some kind to represent and validate our
    # client-side form data. For example, WTForms is a library that will
    # handle this for us, and we use a custom LoginForm to validate.
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
            return flask.redirect(flask.url_for("login"))
        user = User(username)
        login_user(user)

        print("Login success")
        flask.flash("Logged in successfully.")

        next = flask.request.args.get("next")
        if not is_safe_url(next):
            return flask.abort(400)

        return flask.redirect(next or flask.url_for("login"))
    return flask.render_template("login.html", form=form)


@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    form = LogoutForm()
    if form.validate_on_submit():
        logout_user()
        return flask.redirect(flask.url_for("login"))
    return flask.render_template("logout.html", form=form)
