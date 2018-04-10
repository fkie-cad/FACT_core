# -*- coding: utf-8 -*-
import pytest

from helperFunctions.web_interface import filter_out_illegal_characters, is_superuser
from flask_security.core import AnonymousUser, UserMixin, RoleMixin
from werkzeug.local import LocalProxy


@pytest.mark.parametrize('input_data, expected', [
    ('', ''),
    ('abc', 'abc'),
    ('Größer 2', 'Größer 2'),
    ('{"$test": ["test"]}', 'test test'),
    (None, None)
])
def test_filter_out_illegal_characters(input_data, expected):
    assert filter_out_illegal_characters(input_data) == expected


class role_superuser(RoleMixin):
    name = 'superuser'


class superuser_user(UserMixin):
    id = 1
    roles = [role_superuser]


class normal_user(UserMixin):
    id = 2
    roles = []


@pytest.mark.parametrize('input_data, expected', [
    (AnonymousUser, True),
    (superuser_user, True),
    (normal_user, False)
])
def test_is_superuser_without_auth(input_data, expected):
    proxied_object = LocalProxy(input_data)
    assert is_superuser(proxied_object) == expected
