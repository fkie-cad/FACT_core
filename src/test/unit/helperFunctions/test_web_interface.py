import pytest
from flask_security.core import AnonymousUser, RoleMixin, UserMixin
from werkzeug.local import LocalProxy

from helperFunctions.web_interface import filter_out_illegal_characters, get_radare_endpoint, password_is_legal
from test.common_helper import get_config_for_testing
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


@pytest.mark.parametrize('input_data, expected', [
    ('', False),
    ('123456', True),
    ('abc', True),
    ('1234567890abc', False),
    ('$5$FOOBAR99$f12dcbf3354f40a0ac341f712e4d72b74f4bb788dbc33aa86bd92d23c53188e5', False)
])
def test_password_is_legal(input_data, expected):
    assert password_is_legal(input_data) == expected


def test_get_radare_endpoint():
    config = get_config_for_testing()

    assert config.get('ExpertSettings', 'nginx') == 'false'
    assert get_radare_endpoint(config) == 'http://localhost:8000'

    config.set('ExpertSettings', 'nginx', 'true')
    assert get_radare_endpoint(config) == 'https://localhost/radare'
