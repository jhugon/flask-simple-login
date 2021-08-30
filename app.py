from flask import Flask
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from flask_wtf import FlaskForm
from wtforms import StringField
from flask_debugtoolbar import DebugToolbarExtension

app = Flask(__name__)

app.debug = True
app.config["SECRET_KEY"] = b"dummy"

login_manager = LoginManager()
login_manager.init_app(app)

toolbar = DebugToolbarExtension(app)


class User(UserMixin):
    def __init__(self):
        pass


class LoginForm(Form):
    pass


@app.route("/")
def hello_world():
    return "<html>\n<head></head>\n<body>\n<p>Hello, World!</p>\n</body>\n</html>"


@app.route("/login", methods=["GET", "POST"])
def login():
    # Here we use a class of some kind to represent and validate our
    # client-side form data. For example, WTForms is a library that will
    # handle this for us, and we use a custom LoginForm to validate.
    form = LoginForm()
    if form.validate_on_submit():
        # Login and validate the user.
        # user should be an instance of your `User` class
        login_user(user)

        flask.flash("Logged in successfully.")

        next = flask.request.args.get("next")
        # is_safe_url should check if the url is safe for redirects.
        # See http://flask.pocoo.org/snippets/62/ for an example.
        if not is_safe_url(next):
            return flask.abort(400)

        return flask.redirect(next or flask.url_for("index"))
    return flask.render_template("login.html", form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(somewhere)
