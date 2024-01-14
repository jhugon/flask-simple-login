"""
Tests for flask_simple_login.admin
"""
import string

import pytest

from flask_simple_login.admin import validatepassword, validateusername


def generate_nonprintable():
    return (chr(i) for i in range(128) if chr(i) not in string.printable)


def test_validateusername() -> None:
    minlen = 3
    maxlen = 30
    for i in [*range(50), 1000]:
        validlen = i >= minlen and i <= maxlen
        if validlen:
            validateusername("a" * i)
        else:
            with pytest.raises(Exception):
                validateusername("a" * i)
    for x in string.whitespace:
        with pytest.raises(Exception):
            validateusername(x * minlen)
    for x in generate_nonprintable():
        with pytest.raises(Exception):
            validateusername(x * minlen)


def test_validatepassword() -> None:
    minlen = 8
    maxlen = 30
    for i in [*range(50), 1000]:
        validlen = i >= minlen and i <= maxlen
        if validlen:
            validatepassword("a" * i)
        else:
            with pytest.raises(Exception):
                validatepassword("a" * i)
    for x in string.whitespace:
        with pytest.raises(Exception):
            validatepassword(x * minlen)
    for x in generate_nonprintable():
        with pytest.raises(Exception):
            validatepassword(x * minlen)
