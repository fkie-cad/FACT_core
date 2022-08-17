import logging
from base64 import b64encode
from time import gmtime, time
from zlib import compress

import pytest

import web_interface.filter as flt

UNSORTABLE_LIST = [[], ()]

# pylint: disable=invalid-name


def test_set_limit_for_data_to_chart():
    limit = 5
    label_list = ['a', 'b', 'c', 'd', 'e', 'f', 'g']
    value_list = [1, 2, 3, 4, 5, 6, 7]
    expected_result = (['a', 'b', 'c', 'd', 'e', 'rest'], [1, 2, 3, 4, 5, 13])
    assert flt.set_limit_for_data_to_chart(label_list, limit, value_list) == expected_result


@pytest.mark.parametrize(
    'input_data, expected_result',
    [
        (
            [('NX enabled', 1696, 0.89122), ('NX disabled', 207, 0.10878), ('Canary enabled', 9, 0.00473)],
            {
                'labels': ['NX enabled', 'NX disabled', 'Canary enabled'],
                'datasets': [
                    {
                        'data': [1696, 207, 9],
                        'percentage': [0.89122, 0.10878, 0.00473],
                        'backgroundColor': ['#4062fa', '#f4c069', '#4062fa'],
                        'borderWidth': 0,
                        'links': 'null',
                    }
                ],
            }
        ), ([()], None)
    ]
)
def test_data_to_chart_with_value_percentage_pairs(input_data, expected_result):
    assert flt.data_to_chart_with_value_percentage_pairs(input_data) == expected_result


def test_get_all_uids_in_string():
    test_string = (
        '{\'d41c0f1431b39b9db565b4e32a5437c61c77762a3f4401bac3bafa4887164117_24\', '
        '\'f7c927fb0c209035c7e6939bdd00eabdaada429f2ee9aeca41290412c8c79759_25\' , '
        '\'deaa23651f0a9cc247a20d0e0a78041a8e40b144e21b82081ecb519dd548eecf_24494080\'}'
    )
    result = flt.get_all_uids_in_string(test_string)
    assert len(result) == 3, 'not all uids found'
    assert 'd41c0f1431b39b9db565b4e32a5437c61c77762a3f4401bac3bafa4887164117_24' in result, 'first uid not found'
    assert 'f7c927fb0c209035c7e6939bdd00eabdaada429f2ee9aeca41290412c8c79759_25' in result, 'second uid not found'
    assert 'deaa23651f0a9cc247a20d0e0a78041a8e40b144e21b82081ecb519dd548eecf_24494080' in result, 'third uid not found'


def test_handle_uids():
    test_string = 'foo d41c0f1431b39b9db565b4e32a5437c61c77762a3f4401bac3bafa4887164117_24 bar'
    result = flt.uids_to_link(test_string)
    expected_result = (
        'foo <a href="/analysis/d41c0f1431b39b9db565b4e32a5437c61c77762a3f4401bac3bafa4887164117_24/'
        'ro/None">d41c0f1431b39b9db565b4e32a5437c61c77762a3f4401bac3bafa4887164117_24</a> bar'
    )
    assert result == expected_result, 'output not correct'


def check_nice_list_output(input_data):
    result = flt.list_group(input_data)
    assert result == '<ul class="list-group list-group-flush">\n\t<li class="list-group-item">a</li>\n\t<li class="list-group-item">b</li>\n</ul>\n', 'output not correct'


def test_nice_list_set():
    check_nice_list_output(set('ab'))


def test_nice_list_list():
    check_nice_list_output(['a', 'b'])


def test_list_to_line_break_string():
    input_data = set('ab')
    assert flt.list_to_line_break_string(input_data) == 'a\nb\n'


@pytest.mark.parametrize('input_data, expected_result', [
    (['b', 'a'], 'b\na\n'),
    (None, None),
])
def test_list_to_line_break_string_no_sort(input_data, expected_result):
    assert flt.list_to_line_break_string_no_sort(input_data) == expected_result


def test_nice_unix_time_stamp():
    input_data = 1459427460
    assert flt.nice_unix_time(input_data).startswith('2016-03-31')
    assert flt.nice_unix_time(input_data).endswith(':31:00')

    input_data = 1459427460.4
    assert flt.nice_unix_time(input_data).startswith('2016-03-31')
    assert flt.nice_unix_time(input_data).endswith(':31:00')

    assert flt.nice_unix_time('test') == 'test'


def test_sort_chart_list_by_value():
    test_list = [['a', 1], ['b', 2]]
    result = flt.sort_chart_list_by_value(test_list)
    assert result == [['b', 2], ['a', 1]]


def test_sort_chart_list_by_name():
    test_list = [['b', 2], ['a', 1]]
    result = flt.sort_chart_list_by_name(test_list)
    assert result == [['a', 1], ['b', 2]]


@pytest.mark.parametrize(
    'input_data, keyword_args, expected_output',
    [
        ('online', {}, '<span style="color:green;">online</span>'),
        ('offline', {}, '<span style="color:red;">offline</span>'),
        ('foo', {}, 'foo'),
        ('foo', {
            'green': ['*']
        }, '<span style="color:green;">foo</span>'),
        ('foo', {
            'red': ['*']
        }, '<span style="color:red;">foo</span>'),
    ]
)
def test_text_highlighter(input_data, keyword_args, expected_output):
    assert flt.text_highlighter(input_data, **keyword_args) == expected_output


@pytest.mark.parametrize(
    'input_data, expected_output', [
        ('clean', 'color:green'),
        (0, 'color:green'),
        ('foo', 'color:red'),
        (9999, 'color:red'),
        (None, 'color:red'),
    ]
)
def test_infection_color(input_data, expected_output):
    assert expected_output in flt.infection_color(input_data)


def test_fix_cwe_valid_string():
    assert flt.fix_cwe('[CWE467] (Use of sizeof on a Pointer Type)') == '467'


def test_fix_cwe_invalid_string():
    assert flt.fix_cwe('something_really_strange') == ''


def test_replace_underscore():
    assert flt.replace_underscore_filter('a_b') == 'a b'


def test_base64_filter():
    assert flt.encode_base64_filter(b'test') == 'dGVzdA=='


@pytest.mark.parametrize(
    'input_data, verbose, expected',
    [
        (1000, False, '1000.00 Byte'), (1024, False, '1.00 KiB'), (1024 * 1024, False, '1.00 MiB'),
        (1234.1234, False, '1.21 KiB'), (1000, True, '1000.00 Byte (1,000 bytes)'), (b'abc', False, 'not available'),
        (None, False, 'not available')
    ]
)
def test_byte_number_filter(input_data, verbose, expected):
    assert flt.byte_number_filter(input_data, verbose) == expected


@pytest.mark.parametrize(
    'input_data, expected',
    [(b'abc', b'abc'), (123, '123'), (1234, '1,234'), (1234.1234, '1,234.12'), (None, 'not available')]
)
def test_nice_number(input_data, expected):
    assert flt.nice_number_filter(input_data) == expected


@pytest.mark.parametrize(
    'input_data, expected',
    [
        (b'abc', 'abc'), (1234, '1,234'),
        (
            [1, 3],
            '<ul class="list-group list-group-flush">\n\t<li class="list-group-item">1</li>\n\t<li class="list-group-item">3</li>\n</ul>\n'
        ), ({
            'a': 1
        }, 'a: 1<br />'), (gmtime(0), '1970-01-01 - 00:00:00'), ('a_b', 'a b'), (gmtime, gmtime)
    ]
)
def test_generic_nice_representation(input_data, expected):
    assert flt.generic_nice_representation(input_data) == expected


@pytest.mark.parametrize('score, class_', [('low', 'active'), ('medium', 'warning'), ('high', 'danger')])
def test_vulnerability_class_success(score, class_):
    assert flt.vulnerability_class(score) == class_


@pytest.mark.parametrize('score', [None, '', 'bad', 5])
def test_vulnerability_class_bad(score):
    assert flt.vulnerability_class(score) is None


def test_sort_users_by_name():
    class UserMock:
        def __init__(self, id_, name):
            self.id = id_
            self.email = name

    user_1 = UserMock(1, 'b')
    user_2 = UserMock(2, 'd')
    user_3 = UserMock(3, 'a')
    user_4 = UserMock(4, 'c')
    user_list = [user_1, user_2, user_3, user_4]

    assert flt.sort_users_by_name(user_list) == [user_3, user_1, user_4, user_2]


class CurrentUserMock:
    def __init__(self, is_authenticated, roles):
        self.is_authenticated = is_authenticated
        self.roles = roles

    def has_role(self, role):
        return role in self.roles


@pytest.mark.parametrize(
    'user, role, expected_result',
    [
        (CurrentUserMock(False, []), 'manage_users', False),
        (CurrentUserMock(False, ['superuser']), 'manage_users', False),
        (CurrentUserMock(True, []), 'manage_users', False),
        (CurrentUserMock(True, ['superuser']), 'manage_users', True),
    ]
)
def test_user_has_role(user, role, expected_result):
    assert flt.user_has_role(user, role) == expected_result


def test_sort_roles_by_number_of_privileges():
    roles = ['a', 'b', 'c']
    privileges = {
        'p_1': ['b'],
        'p_2': ['a', 'b', 'c'],
        'p_3': ['b', 'c'],
        'p_4': [],
    }
    result = flt.sort_roles_by_number_of_privileges(roles, privileges)
    assert result == ['a', 'c', 'b']


def test_filter_format_string_list_with_offset():
    test_input = [(4, 'abc'), (7, 'abc'), (256, 'def'), (12, 'ghi')]
    expected_result = '  4: abc\n' \
                      '  7: abc\n' \
                      ' 12: ghi\n' \
                      '256: def'
    result = flt.filter_format_string_list_with_offset(test_input)
    assert result == expected_result

    assert flt.filter_format_string_list_with_offset([]) == ''


def test_filter_decompress():
    test_string = 'test123'
    assert flt.decompress(b64encode(compress(test_string.encode())).decode()) == test_string
    assert flt.decompress(test_string) == test_string
    assert flt.decompress(None) is None


@pytest.mark.parametrize(
    'list_of_dicts, expected_result', [
        ([], set()), ([{
            '1': ''
        }], {'1'}), ([{
            '1': ''
        }, {
            '1': '', '2': ''
        }, {
            '1': '', '2': '', '3': ''
        }], {'1', '2', '3'})
    ]
)
def test_get_unique_keys_from_list_of_dicts(list_of_dicts, expected_result):
    assert flt.get_unique_keys_from_list_of_dicts(list_of_dicts) == expected_result


@pytest.mark.parametrize(
    'function, input_data, expected_output, error_message',
    [
        (flt._get_sorted_list, UNSORTABLE_LIST, UNSORTABLE_LIST, 'Could not sort list'),  # pylint: disable=protected-access
        (flt.sort_comments, UNSORTABLE_LIST, [], 'Could not sort comment list'),
        (flt.sort_chart_list_by_name, UNSORTABLE_LIST, [], 'Could not sort chart list'),
        (flt.sort_chart_list_by_value, UNSORTABLE_LIST, [], 'Could not sort chart list'),
    ]
)
def test_error_logging(function, input_data, expected_output, error_message, caplog):
    with caplog.at_level(logging.WARNING):
        assert function(input_data) == expected_output
        assert error_message in caplog.messages[0]


@pytest.mark.parametrize(
    'input_data, expected_result', [
        ('abc', 'abc'),
        ('^$.[]|()?*+{}', '\\^\\$\\.\\[\\]\\|\\(\\)\\?\\*\\+\\{\\}'),
    ]
)
def test_comment_out_regex_meta_chars(input_data, expected_result):
    assert flt.comment_out_regex_meta_chars(input_data) == expected_result


@pytest.mark.parametrize(
    'input_data, additional, expected_result',
    [
        ('real_result', None, True),
        ('analysis_date', None, False),
        ('real_result', ['additional_key'], True),
        ('filtered_result', ['filtered_result'], False),
    ]
)
def test_is_not_mandatory_analysis_entry(input_data, additional, expected_result):
    assert flt.is_not_mandatory_analysis_entry(input_data, additional) is expected_result


def test_version_links_no_analysis():
    links = flt.create_firmware_version_links([('uid_123', '1.0'), ('uid_234', '1.1')])
    assert '<a href="/analysis/uid_123">1.0</a>' in links
    assert '<a href="/analysis/uid_234">1.1</a>' in links


def test_version_links_with_analysis():
    links = flt.create_firmware_version_links([('uid_123', '1.0'), ('uid_234', '1.1')], 'foo')
    assert '<a href="/analysis/uid_123/foo">1.0</a>' in links
    assert '<a href="/analysis/uid_234/foo">1.1</a>' in links


def test_random_collapse_id():
    collapse_id = flt.random_collapse_id()
    assert isinstance(collapse_id, str)
    assert not collapse_id[0].isnumeric()


@pytest.mark.parametrize('time_diff, expected_result', [(5, '0:00:05'), (83, '0:01:23'), (5025, '1:23:45')])
def test_remaining_time(time_diff, expected_result):
    assert flt.format_duration(flt.elapsed_time(time() - time_diff)) == expected_result


@pytest.mark.parametrize(
    'input_string, expected_result',
    [
        ('foo_bar-1-23', 'foo_bar-1-23'),
        ('CVE-1-2', '<a href="https://nvd.nist.gov/vuln/detail/CVE-1-2">CVE-1-2</a>'),
        (
            'a CVE-1-2 b CVE-3-4 c',
            'a <a href="https://nvd.nist.gov/vuln/detail/CVE-1-2">CVE-1-2</a> b <a href="https://nvd.nist.gov/vuln/detail/CVE-3-4">CVE-3-4</a> c'
        ),
    ]
)
def test_replace_cve_with_link(input_string, expected_result):
    assert flt.replace_cve_with_link(input_string) == expected_result


@pytest.mark.parametrize(
    'input_string, expected_result',
    [
        ('foo_bar-1', 'foo_bar-1'),
        ('CWE-123', '<a href="https://cwe.mitre.org/data/definitions/123.html">CWE-123</a>'),
        (
            'a CWE-1 b CWE-1234 c',
            'a <a href="https://cwe.mitre.org/data/definitions/1.html">CWE-1</a> b <a href="https://cwe.mitre.org/data/definitions/1234.html">CWE-1234</a> c'
        ),
    ]
)
def test_replace_cwe_with_link(input_string, expected_result):
    assert flt.replace_cwe_with_link(input_string) == expected_result


@pytest.mark.parametrize(
    'input_dict, expected_result',
    [
        ({}, {}),
        (
            {
                'cve_id1': {
                    'score2': '6.4', 'score3': 'N/A'
                },
                'cve_id4': {
                    'score2': '3.5', 'score3': 'N/A'
                },
                'cve_id5': {
                    'score2': '7.4', 'score3': 'N/A'
                },
            },
            {
                'cve_id5': {
                    'score2': '7.4', 'score3': 'N/A'
                },
                'cve_id1': {
                    'score2': '6.4', 'score3': 'N/A'
                },
                'cve_id4': {
                    'score2': '3.5', 'score3': 'N/A'
                },
            }
        )
    ]
)
def test_sort_cve_result(input_dict, expected_result):
    result = dict(flt.sort_cve_results(input_dict))
    assert result == expected_result

    for item1, item2 in zip(result, expected_result):
        assert item1 == item2


@pytest.mark.parametrize(
    'input_dts, expected_result',
    [
        ('', ''),
        ('data = [01 23 45 67 89 ab cd ef 01 23 45 67 89 ab cd ef];', 'data = (BINARY DATA ...);'),
        ('data = <0x01 0x2345 0x67 0x89 0xabcdef 0x1234 0x56 0x78 0x90 0xab 0xcd>;', 'data = (BINARY DATA ...);'),
        ('data = [01 23 45 67];', 'data = [01 23 45 67];'),  # short entries should not be replaced
        ('data = <0x01 0x2345 0x67>;', 'data = <0x01 0x2345 0x67>;'),  # short entries should not be replaced
    ]
)
def test_hide_dts_data(input_dts, expected_result):
    assert flt.hide_dts_binary_data(input_dts) == expected_result


@pytest.mark.parametrize(
    'input_, expected_result',
    [
        ('', ''),
        ('foo', 'foo'),
        (
            ':37:4e:47:02:4e:2d:\n    c0:4f:2f:b3:94:e1:41:2e:2d:90:10:fc:82:92:8b:\n    0f:22:df:f2:fc:2c:ab:52:55',
            'c0:4f:2f:b3:94:e1:41:2e:2d:90:10:fc:82:92:8b:'
        ),
    ]
)
def test_get_searchable_crypto_block(input_, expected_result):
    assert flt.get_searchable_crypto_block(input_) == expected_result
