import string
import getpass
import sys

import click
import flask
from werkzeug.security import generate_password_hash

from .users import UserInfoEnum, get_user_info_store

def add_admin_commands(auth,db,DBUser):
    "add admin commands to blueprint 'auth'"

    @auth.cli.command("initdb",help="initialize database login user table")
    def initdb():
        app = flask.current_app
        with app.app_context():
            match get_user_info_store():
                case UserInfoEnum.USERTEXT:
                    print("Error: No database to init in text file mode. Check the LOGIN_USER_INFO_STORE_TYPE flask config var.",file=sys.stderr)
                    sys.exit(1)
                case UserInfoEnum.USERDBTABLE:
                    db.create_all()
                case _:
                    raise Exception("Unexpected UserInfoEnum")
        print("User database table created!")
    
    @auth.cli.command("adduser",help="Adds user to the current app's user storage. Will ask for password")
    @click.argument("username")
    def adduser(username):
        app = flask.current_app
        with app.app_context():
            match get_user_info_store():
                case UserInfoEnum.USERTEXT:
                    append_user_file_line(app,username)
                case UserInfoEnum.USERDBTABLE:
                    adduserdb(app,username)
                case _:
                    raise Exception("Unexpected UserInfoEnum")
        print ("Successfully added new user")

    @auth.cli.command("deleteuser",help="Deletes user from the current app's user storage.")
    @click.argument("username")
    def deleteuser(username):
        app = flask.current_app
        with app.app_context():
            match get_user_info_store():
                case UserInfoEnum.USERTEXT:
                    raise NotImplementedError("Not implemented for text file user info storage")
                case UserInfoEnum.USERDBTABLE:
                    try:
                        dbuser = db.session.execute(db.select(DBUser).filter_by(username=username)).scalar_one()
                    except NoResultFound:
                        print("Error: username not found. Exiting.",file=sys.stderr)
                        sys.exit(1)
                    else:
                        db.session.delete(dbuser)
                        db.session.commit()
                case _:
                    raise Exception("Unexpected UserInfoEnum")
        print ("Successfully deleted user")

    @auth.cli.command("changeuserpassword",help="Change a user's password.")
    @click.argument("username")
    def changeuserpassword(username):
        app = flask.current_app
        with app.app_context():
            match get_user_info_store():
                case UserInfoEnum.USERTEXT:
                    raise NotImplementedError("Not implemented for text file user info storage")
                case UserInfoEnum.USERDBTABLE:
                    try:
                        dbuser = db.session.execute(db.select(DBUser).filter_by(username=username)).scalar_one()
                    except NoResultFound:
                        print("Error: username not found. Exiting.",file=sys.stderr)
                        sys.exit(1)
                    else:
                        print("NEW PASSWORD:")
                        dbuser.passwordhash = validateusernamehashpassword(username)
                        db.session.commit()
                case _:
                    raise Exception("Unexpected UserInfoEnum")
        print ("Successfully updated password")


    def adduserdb(app, username):
        with app.app_context():
            passwordhash = validateusernamehashpassword(username)
            dbuser = DBUser(username=username,passwordhash=passwordhash)
            db.session.add(dbuser)
            db.session.commit()

    def append_user_file_line(app,username):
        fn = app.config["LOGIN_USER_FILE_PATH"]
        print(f"Adding to userfile: '{fn}'")
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
        line = make_user_file_line(username)
        with open(fn,"a") as userfile:
            userfile.write(line+"\n")


    def make_user_file_line(username):
        """
        The user file line is of the form: "<username> <password hash>"
        No spaces or control characters are allowed in the username or password hash

        The user file only lists these lines
        """
        result = username + " "
        passwordHash = validateusernamehashpassword(username)
        result += passwordHash
        return result


    def validateusernamehashpassword(username):
        if len(username) < 3 or len(username) > 30:
            raise Exception(
                f'Error: username "{username}" should be between 3 and 30 characters long.'
            )
        for x in username:
            if x in string.whitespace or not (x in string.printable):
                raise Exception(
                    f'Error: username "{username}" contains a space or non-printable characters. This is not allowed.'
                )
        password = getpass.getpass("Enter password: ")
        password2 = getpass.getpass("Re-enter password: ")
        if password != password2:
            print("Error: passwords don't match! Exiting.",file=sys.stderr)
            sys.exit(1)
        if len(password) < 3 or len(password) > 30:
            raise Exception(f"Error: password should be between 8 and 30 characters long.")
        passwordHash = generate_password_hash(
            password, "pbkdf2:sha256:100000", salt_length=16
        )
        for x in passwordHash:
            if x in string.whitespace or not (x in string.printable):
                raise Exception(
                    f'Error: passwordHash "{username}" contains a space or non-printable characters. This is not allowed. Try again, a different salt may help.y'
                )
        return passwordHash
