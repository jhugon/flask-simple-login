"""
The classes and methods you use externally are in here
"""
# ruff: noqa: F401
from flask_login import current_user, login_required

from .web import setup_auth
