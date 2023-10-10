import pytest
from flask_security.core import AnonymousUser, RoleMixin, UserMixin
from werkzeug.local import LocalProxy

from helperFunctions.web_interface import (
    _format_si_prefix,
    cap_length_of_element,
    filter_out_illegal_characters,
    format_time,
    password_is_legal,
)
from web_interface.security.authentication import user_has_privilege


@pytest.mark.parametrize(
    ('input_data', 'expected'),
    [('', ''), ('abc', 'abc'), ('Größer 2', 'Größer 2'), ('{"$test": ["test"]}', 'test test'), (None, None)],
)
def test_filter_out_illegal_characters(input_data, expected):
    assert filter_out_illegal_characters(input_data) == expected


class RoleSuperuser(RoleMixin):
    name = 'superuser'


class SuperuserUser(UserMixin):
    id = 1
    roles = [RoleSuperuser]  # noqa: RUF012


class NormalUser(UserMixin):
    id = 2
    roles = []  # noqa: RUF012


@pytest.mark.parametrize(
    ('input_data', 'expected'), [(AnonymousUser, True), (SuperuserUser, True), (NormalUser, False)]
)
def test_is_superuser(input_data, expected):
    proxied_object = LocalProxy(input_data)
    assert user_has_privilege(proxied_object) == expected


@pytest.mark.parametrize(
    ('input_data', 'expected'),
    [
        ('', False),
        ('123456', True),
        ('abc', True),
        ('1234567890abc', False),
        ('$5$FOOBAR99$f12dcbf3354f40a0ac341f712e4d72b74f4bb788dbc33aa86bd92d23c53188e5', False),
    ],
)
def test_password_is_legal(input_data, expected):
    assert password_is_legal(input_data) == expected


@pytest.mark.parametrize(
    ('element_in', 'element_out'),
    [
        ('A' * 55, 'A' * 55),
        ('A' * 56, '~' + 'A' * 54),
    ],
)
def test_cap_length_of_element_default(element_in, element_out):
    assert cap_length_of_element(element_in) == element_out


def test_cap_length_of_element_short():
    assert cap_length_of_element('1234', maximum=3) == '~34'


@pytest.mark.parametrize(
    ('number', 'unit', 'expected_output'),
    [
        (1, 'm', '1 m'),
        (0.034, 'g', '34 mg'),
        (0.0000123456789, 's', '12.3 µs'),
        (1234.5, 'm', '1.23 km'),
    ],
)
def test_format_si_prefix(number, unit, expected_output):
    assert _format_si_prefix(number, unit) == expected_output


@pytest.mark.parametrize(
    ('seconds', 'expected_output'),
    [
        (2, '2 s'),
        (0.2, '200 ms'),
        (120, '0:02:00'),
        (100000, '1 day, 3:46:40'),
    ],
)
def test_format_time(seconds, expected_output):
    assert format_time(seconds) == expected_output
