import pytest
from flask_security.core import AnonymousUser, RoleMixin, UserMixin
from werkzeug.local import LocalProxy

from helperFunctions.web_interface import (
    filter_out_illegal_characters, get_radare_endpoint, password_is_legal, split_virtual_path,
    virtual_path_element_to_span
)
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


class RoleSuperuser(RoleMixin):
    name = 'superuser'


class SuperuserUser(UserMixin):
    id = 1
    roles = [RoleSuperuser]


class NormalUser(UserMixin):
    id = 2
    roles = []


@pytest.mark.parametrize('input_data, expected', [
    (AnonymousUser, True),
    (SuperuserUser, True),
    (NormalUser, False)
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


@pytest.mark.parametrize('hid, uid, expected_output', [
    ('foo', 'bar', 'label-default">foo'),
    ('foo', 'a152ccc610b53d572682583e778e43dc1f24ddb6577255bff61406bc4fb322c3_21078024', 'label-primary"><a'),
])
def test_virtual_path_element_to_span(hid, uid, expected_output):
    assert expected_output in virtual_path_element_to_span(hid, uid, 'root_uid')


@pytest.mark.parametrize('virtual_path, expected_output', [
    ('', []),
    ('a|b|c', ['a', 'b', 'c']),
    ('|a|b|c|', ['a', 'b', 'c']),
])
def test_split_virtual_path(virtual_path, expected_output):
    assert split_virtual_path(virtual_path) == expected_output
