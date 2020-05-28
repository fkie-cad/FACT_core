import logging
from time import gmtime
from zlib import compress

import pytest

from helperFunctions.web_interface import BS_PRIMARY, BS_SECONDARY
from web_interface.filter import (
    _get_sorted_list, byte_number_filter, comment_out_regex_meta_chars, create_firmware_version_links,
    data_to_chart_limited, data_to_chart_with_value_percentage_pairs, decompress, encode_base64_filter,
    filter_format_string_list_with_offset, fix_cwe, generic_nice_representation, get_all_uids_in_string,
    get_unique_keys_from_list_of_dicts, infection_color, is_not_mandatory_analysis_entry, list_group,
    list_to_line_break_string, list_to_line_break_string_no_sort, nice_number_filter, nice_unix_time,
    random_collapse_id, render_analysis_tags, render_tags, replace_underscore_filter, set_limit_for_data_to_chart,
    sort_chart_list_by_name, sort_chart_list_by_value, sort_comments, sort_roles_by_number_of_privileges,
    sort_users_by_name, text_highlighter, uids_to_link, user_has_role, vulnerability_class
)

UNSORTABLE_LIST = [[], ()]

# pylint: disable=invalid-name


def test_set_limit_for_data_to_chart():
    limit = 5
    label_list = ['a', 'b', 'c', 'd', 'e', 'f', 'g']
    value_list = [1, 2, 3, 4, 5, 6, 7]
    expected_result = (['a', 'b', 'c', 'd', 'e', 'rest'], [1, 2, 3, 4, 5, 13])
    assert set_limit_for_data_to_chart(label_list, limit, value_list) == expected_result


@pytest.mark.parametrize('input_data, expected_result', [
    (
        [('NX enabled', 1696, 0.89122), ('NX disabled', 207, 0.10878), ('Canary enabled', 9, 0.00473)],
        {
            'labels': ['NX enabled', 'NX disabled', 'Canary enabled'],
            'datasets': [{
                'data': [1696, 207, 9],
                'percentage': [0.89122, 0.10878, 0.00473],
                'backgroundColor': [BS_PRIMARY, BS_SECONDARY, BS_PRIMARY],
                'borderColor': [BS_PRIMARY, BS_SECONDARY, BS_PRIMARY],
                'borderWidth': 1
            }]
        }
    ),
    ([()], None)
])
def test_data_to_chart_with_value_percentage_pairs(input_data, expected_result):
    assert data_to_chart_with_value_percentage_pairs(input_data) == expected_result


@pytest.mark.parametrize('input_data, expected_result', [
    (
        [('NX enabled', 1696), ('NX disabled', 207), ('Canary enabled', 9)],
        {
            'labels': ['NX enabled', 'NX disabled', 'Canary enabled'],
            'datasets': [{
                'data': [1696, 207, 9],
                'backgroundColor': [BS_PRIMARY, BS_SECONDARY, BS_PRIMARY],
                'borderColor': [BS_PRIMARY, BS_SECONDARY, BS_PRIMARY],
                'borderWidth': 1
            }]
        }
    ),
    ([()], None)
])
def test_data_to_chart_limited(input_data, expected_result):
    assert data_to_chart_limited(input_data) == expected_result


def test_get_all_uids_in_string():
    test_string = ('{\'d41c0f1431b39b9db565b4e32a5437c61c77762a3f4401bac3bafa4887164117_24\', '
                   '\'f7c927fb0c209035c7e6939bdd00eabdaada429f2ee9aeca41290412c8c79759_25\' , '
                   '\'deaa23651f0a9cc247a20d0e0a78041a8e40b144e21b82081ecb519dd548eecf_24494080\'}')
    result = get_all_uids_in_string(test_string)
    assert len(result) == 3, 'not all uids found'
    assert 'd41c0f1431b39b9db565b4e32a5437c61c77762a3f4401bac3bafa4887164117_24' in result, 'first uid not found'
    assert 'f7c927fb0c209035c7e6939bdd00eabdaada429f2ee9aeca41290412c8c79759_25' in result, 'second uid not found'
    assert 'deaa23651f0a9cc247a20d0e0a78041a8e40b144e21b82081ecb519dd548eecf_24494080' in result, 'third uid not found'


def test_handle_uids():
    test_string = 'foo d41c0f1431b39b9db565b4e32a5437c61c77762a3f4401bac3bafa4887164117_24 bar'
    result = uids_to_link(test_string)
    expected_result = ('foo <a href="/analysis/d41c0f1431b39b9db565b4e32a5437c61c77762a3f4401bac3bafa4887164117_24/'
                       'ro/None">d41c0f1431b39b9db565b4e32a5437c61c77762a3f4401bac3bafa4887164117_24</a> bar')
    assert result == expected_result, 'output not correct'


def check_nice_list_output(input_data):
    result = list_group(input_data)
    assert result == '<ul class="list-group list-group-flush">\n\t<li class="list-group-item">a</li>\n\t<li class="list-group-item">b</li>\n</ul>\n', 'output not correct'


def test_nice_list_set():
    check_nice_list_output(set('ab'))


def test_nice_list_list():
    check_nice_list_output(['a', 'b'])


def test_list_to_line_break_string():
    input_data = set('ab')
    assert list_to_line_break_string(input_data) == 'a\nb\n'


@pytest.mark.parametrize('input_data, expected_result', [
    (['b', 'a'], 'b\na\n'),
    (None, None),
])
def test_list_to_line_break_string_no_sort(input_data, expected_result):
    assert list_to_line_break_string_no_sort(input_data) == expected_result


def test_nice_unix_time_stamp():
    input_data = 1459427460
    assert nice_unix_time(input_data).startswith('2016-03-31')
    assert nice_unix_time(input_data).endswith(':31:00')

    input_data = 1459427460.4
    assert nice_unix_time(input_data).startswith('2016-03-31')
    assert nice_unix_time(input_data).endswith(':31:00')

    assert nice_unix_time('test') == 'test'


def test_sort_chart_list_by_value():
    test_list = [['a', 1], ['b', 2]]
    result = sort_chart_list_by_value(test_list)
    assert result == [['b', 2], ['a', 1]]


def test_sort_chart_list_by_name():
    test_list = [['b', 2], ['a', 1]]
    result = sort_chart_list_by_name(test_list)
    assert result == [['a', 1], ['b', 2]]


@pytest.mark.parametrize('input_data, keyword_args, expected_output', [
    ('online', {}, '<span style="color:green;">online</span>'),
    ('offline', {}, '<span style="color:red;">offline</span>'),
    ('foo', {}, 'foo'),
    ('foo', {'green': ['*']}, '<span style="color:green;">foo</span>'),
    ('foo', {'red': ['*']}, '<span style="color:red;">foo</span>'),
])
def test_text_highlighter(input_data, keyword_args, expected_output):
    assert text_highlighter(input_data, **keyword_args) == expected_output


@pytest.mark.parametrize('input_data, expected_output', [
    ('clean', 'color:green'),
    (0, 'color:green'),
    ('foo', 'color:red'),
    (9999, 'color:red'),
    (None, 'color:red'),
])
def test_infection_color(input_data, expected_output):
    assert expected_output in infection_color(input_data)


def test_fix_cwe_valid_string():
    assert fix_cwe("[CWE467] (Use of sizeof on a Pointer Type)") == "467"


def test_fix_cwe_invalid_string():
    assert fix_cwe("something_really_strange") == ""


def test_replace_underscore():
    assert replace_underscore_filter('a_b') == 'a b'


def test_base64_filter():
    assert encode_base64_filter(b'test') == 'dGVzdA=='


@pytest.mark.parametrize('input_data, verbose, expected', [
    (1000, False, '1000.00 Byte'),
    (1024, False, '1.00 KiB'),
    (1024 * 1024, False, '1.00 MiB'),
    (1234.1234, False, '1.21 KiB'),
    (1000, True, '1000.00 Byte (1,000 bytes)'),
    (b'abc', False, 'not available'),
    (None, False, 'not available')
])
def test_byte_number_filter(input_data, verbose, expected):
    assert byte_number_filter(input_data, verbose) == expected


@pytest.mark.parametrize('input_data, expected', [
    (b'abc', b'abc'),
    (123, '123'),
    (1234, '1,234'),
    (1234.1234, '1,234.12'),
    (None, 'not available')
])
def test_nice_number(input_data, expected):
    assert nice_number_filter(input_data) == expected


@pytest.mark.parametrize('input_data, expected', [
    (b'abc', 'abc'),
    (1234, '1,234'),
    ([1, 3], '<ul class="list-group list-group-flush">\n\t<li class="list-group-item">1</li>\n\t<li class="list-group-item">3</li>\n</ul>\n'),
    ({'a': 1}, 'a: 1<br />'),
    (gmtime(0), '1970-01-01 - 00:00:00'),
    ('a_b', 'a b'),
    (gmtime, gmtime)
])
def test_generic_nice_representation(input_data, expected):
    assert generic_nice_representation(input_data) == expected


@pytest.mark.parametrize('tag_dict, output', [
    ({'a': 'danger'}, '<span class="badge badge-danger " style="font-size: 14px;">a</span>\n'),
    (
        {'a': 'danger', 'b': 'primary'},
        '<span class="badge badge-danger " style="font-size: 14px;">a</span>\n'
        '<span class="badge badge-primary " style="font-size: 14px;">b</span>\n'
    ),
    (None, '')
])
def test_render_tags(tag_dict, output):
    assert render_tags(tag_dict) == output


def test_empty_analysis_tags():
    assert render_analysis_tags(dict()) == ''


def test_render_analysis_tags_success():
    tags = {'such plugin': {'tag': {'color': 'success', 'value': 'wow'}}}
    output = render_analysis_tags(tags)
    assert 'badge-success' in output
    assert '>wow<' in output


def test_render_analysis_tags_fix():
    tags = {'such plugin': {'tag': {'color': 'very color', 'value': 'wow'}}}
    output = render_analysis_tags(tags)
    assert 'badge-primary' in output
    assert '>wow<' in output


def test_render_analysis_tags_bad_type():
    tags = {'such plugin': {42: {'color': 'very color', 'value': 'wow'}}}
    with pytest.raises(AttributeError):
        render_analysis_tags(tags)


@pytest.mark.parametrize('score, class_', [('low', 'active'), ('medium', 'warning'), ('high', 'danger')])
def test_vulnerability_class_success(score, class_):
    assert vulnerability_class(score) == class_


@pytest.mark.parametrize('score', [None, '', 'bad', 5])
def test_vulnerability_class_bad(score):
    assert vulnerability_class(score) is None


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

    assert sort_users_by_name(user_list) == [user_3, user_1, user_4, user_2]


class CurrentUserMock:
    def __init__(self, is_authenticated, roles):
        self.is_authenticated = is_authenticated
        self.roles = roles

    def has_role(self, role):
        return role in self.roles


@pytest.mark.parametrize('user, role, expected_result', [
    (CurrentUserMock(False, []), 'manage_users', False),
    (CurrentUserMock(False, ['superuser']), 'manage_users', False),
    (CurrentUserMock(True, []), 'manage_users', False),
    (CurrentUserMock(True, ['superuser']), 'manage_users', True),
])
def test_user_has_role(user, role, expected_result):
    assert user_has_role(user, role) == expected_result


def test_sort_roles_by_number_of_privileges():
    roles = ['a', 'b', 'c']
    privileges = {
        'p_1': ['b'],
        'p_2': ['a', 'b', 'c'],
        'p_3': ['b', 'c'],
        'p_4': [],
    }
    result = sort_roles_by_number_of_privileges(roles, privileges)
    assert result == ['a', 'c', 'b']


def test_filter_format_string_list_with_offset():
    test_input = [(4, 'abc'), (7, 'abc'), (256, 'def'), (12, 'ghi')]
    expected_result = '  4: abc\n' \
                      '  7: abc\n' \
                      ' 12: ghi\n' \
                      '256: def'
    result = filter_format_string_list_with_offset(test_input)
    assert result == expected_result

    assert filter_format_string_list_with_offset([]) == ''


def test_filter_decompress():
    test_string = "test123"
    assert decompress(compress(test_string.encode())) == test_string
    assert decompress(test_string.encode()) == test_string
    assert decompress(test_string) == test_string
    assert decompress(None) is None


@pytest.mark.parametrize('list_of_dicts, expected_result', [
    ([], set()),
    ([{'1': ''}], {'1'}),
    ([{'1': ''}, {'1': '', '2': ''}, {'1': '', '2': '', '3': ''}], {'1', '2', '3'})
])
def test_get_unique_keys_from_list_of_dicts(list_of_dicts, expected_result):
    assert get_unique_keys_from_list_of_dicts(list_of_dicts) == expected_result


@pytest.mark.parametrize('function, input_data, expected_output, error_message', [
    (_get_sorted_list, UNSORTABLE_LIST, UNSORTABLE_LIST, 'Could not sort list'),
    (sort_comments, UNSORTABLE_LIST, [], 'Could not sort comment list'),
    (sort_chart_list_by_name, UNSORTABLE_LIST, [], 'Could not sort chart list'),
    (sort_chart_list_by_value, UNSORTABLE_LIST, [], 'Could not sort chart list'),
])
def test_error_logging(function, input_data, expected_output, error_message, caplog):
    with caplog.at_level(logging.WARNING):
        assert function(input_data) == expected_output
        assert error_message in caplog.messages[0]


@pytest.mark.parametrize('input_data, expected_result', [
    ('abc', 'abc'),
    ('^$.[]|()?*+{}', '\\^\\$\\.\\[\\]\\|\\(\\)\\?\\*\\+\\{\\}'),
])
def test_comment_out_regex_meta_chars(input_data, expected_result):
    assert comment_out_regex_meta_chars(input_data) == expected_result


@pytest.mark.parametrize('input_data, additional, expected_result', [
    ('real_result', None, True),
    ('analysis_date', None, False),
    ('real_result', ['additional_key'], True),
    ('filtered_result', ['filtered_result'], False),
])
def test_is_not_mandatory_analysis_entry(input_data, additional, expected_result):
    assert is_not_mandatory_analysis_entry(input_data, additional) is expected_result


def test_version_links_no_analysis():
    links = create_firmware_version_links([{'version': '1.0', '_id': 'uid_123'}, {'version': '1.1', '_id': 'uid_234'}])
    assert '<a href="/analysis/uid_123">1.0</a>' in links
    assert '<a href="/analysis/uid_234">1.1</a>' in links


def test_version_links_with_analysis():
    links = create_firmware_version_links([{'version': '1.0', '_id': 'uid_123'}, {'version': '1.1', '_id': 'uid_234'}], 'foo')
    assert '<a href="/analysis/uid_123/foo">1.0</a>' in links
    assert '<a href="/analysis/uid_234/foo">1.1</a>' in links


def test_random_collapse_id():
    collapse_id = random_collapse_id()
    assert isinstance(collapse_id, str)
    assert not collapse_id[0].isnumeric()
