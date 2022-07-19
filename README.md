# flask-simple-login

This module can be used as a [Flask Blueprint](https://flask.palletsprojects.com/en/2.1.x/blueprints/)

## Setting up user file

After installing the package, run:

```bash
flask-simple-login-gen-user-file-line >> userfile.txt
```

You will be asked for a username, the password, and to confirm the password.
You can check that your new user was added to the user file by inspecting its
contents.

The user file line is of the form: `<username> <password hash>` No spaces or
control characters are allowed in the username or password hash

## Running the test server

```bash
./run_debug_server.sh
```

## Adding to your application

Install this package into your path.

Import this in your main flask app file:

```python
from flask_simple_login import (
    login_manager,
    auth,
    User,
    login_required,
)
```

and this once you have done `app = Falsk(__name__)`:

```python
app.register_blueprint(auth)
login_manager.init_app(app)
```

Make sure to set a secure secret key like:

```python
app.config["SECRET_KEY"] = b"dummy"
app.config["SESSION_PROTECTION"] = "strong"
```
