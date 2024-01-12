# flask-simple-login

This module can be used as a [Flask Blueprint](https://flask.palletsprojects.com/en/2.1.x/blueprints/)

## Adding to your application

Install this package into your path.

Import this in your main flask app file:

```python
from flask_simple_login import (
    setup_auth,
    login_required,
    current_user,
)
```

and add this once you have done `app = Flask(__name__)` and have set configuration options (below):

```python
setup_auth(app, db)
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

You must either configure a SQLAlchemy database to store user info. This can
even be a sqlite db. You must set the database URI:

```python
app.config["SQLALCHEMY_DATABASE_URI"] = "..."
```

and setup the database. If you are using Flask-SQLAlchemy elsewhere, just set
it up first, and put it in as the "db" argument to `setup_auth(app,db)`.
Otherwise, do the import `from flask_sqlalchemy import SQLAlchemy` and then:

```python
db = SQLAlchemy
db.init_app(app)
```

and, after the code is setup, you must initialize the DB with:

```bash
flask auth initdb
```

## Managing users

After activating the package as part of your flask app, you can add users with:

```bash
flask auth adduser
```

(You may need to set the env var `FLASK_APP` to your flask app)

Other administrative commands are: `flask auth deleteuser` and `flask auth
changeuserpassword`.

## Running the test server in this package

```bash
./run_debug_server.sh
```
