"""
The classes and methods you actually need are in here
"""
from .users import User, do_login, do_logout, is_safe_url
from flask_login import LoginManager, login_required
