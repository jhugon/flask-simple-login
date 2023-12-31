# flask-simple-login

This module can be used as a [Flask Blueprint](https://flask.palletsprojects.com/en/2.1.x/blueprints/)

## Adding to your application

Install this package into your path.

Import this in your main flask app file:

```python
from flask_simple_login import (
    login_manager,
    auth,
    User,
    login_required,
    current_user,
)
```

and add this once you have done `app = Flask(__name__)`:

```python
app.register_blueprint(auth)
login_manager.init_app(app)
```

Make sure to set a secure secret key like:

```python
app.config["SECRET_KEY"] = b"<secure key>"
app.config["SESSION_PROTECTION"] = "strong"
```

Generate a key with :

```bash
python -c 'import secrets; print(secrets.token_hex())'
```

## User Info Storage

You must either configure users to be loaded from a text file or a SQLAlchemy database

For the userfile:

```python
app.config["LOGIN_USER_FILE_PATH"] = "userfile.txt"
```

For the database, set the table with the login info:

```python
app.config["LOGIN_USER_TABLE"] = "users"
```

and the database URI must also be set:

```python
app.config["SQLALCHEMY_DATABASE_URI"] = "..."
```

## Managing users

After activating the package as part of your flask app, you can add users with:

```bash
flask auth adduser
```

(You may need to set the env var `FLASK_APP` to your flask app)

The userfile will be printed, and you will be asked for a username, the
password, and to confirm the password.  You can check that your new user was
added to the user file by inspecting its contents.

The user file line is of the form: `<username> <password hash>` No spaces or
control characters are allowed in the username or password hash

## Running the test server in this package

```bash
./run_debug_server.sh
```
