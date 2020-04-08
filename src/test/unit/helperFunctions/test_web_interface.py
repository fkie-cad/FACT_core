import pytest
from flask_security.core import AnonymousUser, RoleMixin, UserMixin
from werkzeug.local import LocalProxy

from helperFunctions.web_interface import (
    cap_length_of_element, filter_out_illegal_characters, format_si_prefix, format_time, get_radare_endpoint,
    password_is_legal, split_virtual_path, virtual_path_element_to_span
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
    id = 1  # pylint: disable=invalid-name
    roles = [RoleSuperuser]


class NormalUser(UserMixin):
    id = 2  # pylint: disable=invalid-name
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
    ('foo', 'bar', 'badge-secondary">foo'),
    ('foo', 'a152ccc610b53d572682583e778e43dc1f24ddb6577255bff61406bc4fb322c3_21078024', 'badge-primary">    <a'),
    ('suuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuper/long/human_readable_id', 'bar', '~uuuuuuuuuuuuuuuuuuuuuuuuuuuuper/long/human_readable_id'),
])
def test_virtual_path_element_to_span(hid, uid, expected_output):
    assert expected_output in virtual_path_element_to_span(hid, uid, 'root_uid')


@pytest.mark.parametrize('element_in, element_out', [
    ('A' * 55, 'A' * 55),
    ('A' * 56, '~' + 'A' * 54),
])
def test_cap_length_of_element_default(element_in, element_out):
    assert cap_length_of_element(element_in) == element_out


def test_cap_length_of_element_short():
    assert cap_length_of_element('1234', maximum=3) == '~34'


@pytest.mark.parametrize('virtual_path, expected_output', [
    ('', []),
    ('a|b|c', ['a', 'b', 'c']),
    ('|a|b|c|', ['a', 'b', 'c']),
])
def test_split_virtual_path(virtual_path, expected_output):
    assert split_virtual_path(virtual_path) == expected_output


@pytest.mark.parametrize('number, unit, expected_output', [
    (1, 'm', '1.00 m'),
    (0.034, 'g', '34.00 mg'),
    (0.0000123456789, 's', '12.35 µs'),
    (1234.5, 'm', '1.23 km'),
])
def test_format_si_prefix(number, unit, expected_output):
    assert format_si_prefix(number, unit) == expected_output


@pytest.mark.parametrize('seconds, expected_output', [
    (2, '2.00 s'),
    (0.2, '200.00 ms'),
    (120, '0:02:00'),
    (100000, '1 day, 3:46:40'),
])
def test_format_time(seconds, expected_output):
    assert format_time(seconds) == expected_output
