import string

import flask
from werkzeug.security import generate_password_hash


def append_user_file_line():
    import getpass
    import sys

    fn = flask.current_app.config["LOGIN_USER_FILE_PATH"]
    print(f"Adding to userfile: '{fn}'")
    username = input("Enter username: ")
    try:
        with open(fn,'r') as userfile:
            for line in userfile:
                line = line.strip("\n")
                line_split = line.split(" ")
                if len(line_split) != 2:
                    continue
                if line_split[0] == username:
                    print("Error: username already present. Exiting.",file=sys.stderr)
                    sys.exit(1)
    except FileNotFoundError:
        pass
    password1 = getpass.getpass("Enter password: ")
    password2 = getpass.getpass("Re-enter password: ")
    if password1 != password2:
        print("Error: passwords don't match! Exiting.",file=sys.stderr)
        sys.exit(1)
    line = make_user_file_line(username, password1)
    with open(fn,"a") as userfile:
        userfile.write(line+"\n")


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
