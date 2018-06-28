# -*- coding: utf-8 -*-
import pytest

from flask_security.core import AnonymousUser, UserMixin, RoleMixin
from werkzeug.local import LocalProxy

from helperFunctions.web_interface import filter_out_illegal_characters, _get_rgba, get_js_list_of_n_uniques_colors
from web_interface.security.authentication import user_has_privilege


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
def test_is_superuser(input_data, expected):
    proxied_object = LocalProxy(input_data)
    assert user_has_privilege(proxied_object) == expected


@pytest.mark.parametrize('hue, alpha, saturation, lightness, expected', [
    (0, 0, 0, 0, 'rgba(0, 0, 0, 0)'),
    (0, 1, 0, 0, 'rgba(0, 0, 0, 255)'),
    (0, 1, 0, 1, 'rgba(255, 255, 255, 255)'),
    (0, 1, 1, 1, 'rgba(255, 0, 0, 255)'),
])
def test_get_rgba(hue, alpha, saturation, lightness, expected):
    assert _get_rgba(hue, alpha, saturation, lightness) == expected


def test_get_js_list_of_n_uniques_colors():
    result = get_js_list_of_n_uniques_colors(3)
    assert len(result) == 3
    assert any(isinstance(item, str) for item in result)
    assert any('rgba' in item for item in result)
    assert any(len(item.split(',')) == 4 for item in result)
