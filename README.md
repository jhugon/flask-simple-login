# flask-simple-login

This module can be used as a [Flask Blueprint](https://flask.palletsprojects.com/en/2.1.x/blueprints/) (Work in progress)

## Setting up user file

After installing the package, run:

```
flask-simple-login-gen-user-file-line >> userfile.txt
```

You will be asked for a username, the password, and to confirm the password.
You can check that your new user was added to the user file by inspecting its
contents.

The user file line is of the form: `<username> <password hash>` No spaces or
control characters are allowed in the username or password hash

## Running the test server

```
./run_debug_server.sh
```
