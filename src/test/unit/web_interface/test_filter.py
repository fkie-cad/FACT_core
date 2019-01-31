import unittest
from time import gmtime
from zlib import compress

import pytest

from web_interface.filter import replace_underscore_filter, byte_number_filter, get_all_uids_in_string, nice_list, \
    uids_to_link, list_to_line_break_string, nice_unix_time, nice_number_filter, sort_chart_list_by_value, \
    sort_chart_list_by_name, text_highlighter, generic_nice_representation, list_to_line_break_string_no_sort, \
    encode_base64_filter, render_tags, fix_cwe, set_limit_for_data_to_chart, data_to_chart_with_value_percentage_pairs, \
    data_to_chart_limited, render_analysis_tags, vulnerability_class, sort_users_by_name, user_has_role, \
    sort_roles_by_number_of_privileges, \
    filter_format_string_list_with_offset, decompress, infection_color, get_unique_keys_from_list_of_dicts


class TestWebInterfaceFilter(unittest.TestCase):

    def test_set_limit_for_data_to_chart(self):
        limit = 5
        label_list = ['a', 'b', 'c', 'd', 'e', 'f', 'g']
        value_list = [1, 2, 3, 4, 5, 6, 7]
        self.assertEqual(set_limit_for_data_to_chart(label_list, limit, value_list),
                         (['a', 'b', 'c', 'd', 'e', 'rest'], [1, 2, 3, 4, 5, 13]))

    def test_data_to_chart_with_value_percentage_pairs(self):
        self.maxDiff = None
        data = [('NX enabled', 1696, 0.89122),
                ('NX disabled', 207, 0.10878),
                ('Canary enabled', 9, 0.00473)]
        self.assertEqual(data_to_chart_with_value_percentage_pairs(data),
                         {'labels': ['NX enabled', 'NX disabled', 'Canary enabled'],
                          'datasets': [{'data': [1696, 207, 9],
                                        'percentage': [0.89122, 0.10878, 0.00473],
                                        'backgroundColor': ['#2b669a', '#cce0dc', '#2b669a'],
                                        'borderColor': ['#2b669a', '#cce0dc', '#2b669a'],
                                        'borderWidth': 1}]})

    def test_data_to_chart_limited(self):
        data = [('NX enabled', 1696),
                ('NX disabled', 207),
                ('Canary enabled', 9)]
        self.assertEqual(data_to_chart_limited(data),
                         {'labels': ['NX enabled', 'NX disabled', 'Canary enabled'],
                          'datasets': [{'data': [1696, 207, 9],
                                        'backgroundColor': ['#2b669a', '#cce0dc', '#2b669a'],
                                        'borderColor': ['#2b669a', '#cce0dc', '#2b669a'],
                                        'borderWidth': 1}]})

    def test_get_all_uids_in_string(self):
        test_string = '{\'d41c0f1431b39b9db565b4e32a5437c61c77762a3f4401bac3bafa4887164117_24\', \'f7c927fb0c209035c7e6939bdd00eabdaada429f2ee9aeca41290412c8c79759_25\' , \'deaa23651f0a9cc247a20d0e0a78041a8e40b144e21b82081ecb519dd548eecf_24494080\'}'
        result = get_all_uids_in_string(test_string)
        self.assertEqual(len(result), 3, 'not all uids found')
        self.assertIn('d41c0f1431b39b9db565b4e32a5437c61c77762a3f4401bac3bafa4887164117_24', result, 'first uid not found')
        self.assertIn('f7c927fb0c209035c7e6939bdd00eabdaada429f2ee9aeca41290412c8c79759_25', result, 'second uid not found')
        self.assertIn('deaa23651f0a9cc247a20d0e0a78041a8e40b144e21b82081ecb519dd548eecf_24494080', result, 'third uid not found')

    def test_handle_uids(self):
        test_string = 'foo d41c0f1431b39b9db565b4e32a5437c61c77762a3f4401bac3bafa4887164117_24 bar'
        result = uids_to_link(test_string)
        self.assertEqual(result, 'foo <a href="/analysis/d41c0f1431b39b9db565b4e32a5437c61c77762a3f4401bac3bafa4887164117_24/ro/None">d41c0f1431b39b9db565b4e32a5437c61c77762a3f4401bac3bafa4887164117_24</a> bar', 'output not correct')

    def check_nice_list_output(self, input_data):
        result = nice_list(input_data)
        self.assertEqual(result, '<ul>\n\t<li>a</li>\n\t<li>b</li>\n</ul>\n', 'output not correct')

    def test_nice_list_set(self):
        self.check_nice_list_output(set('ab'))

    def test_nice_list_list(self):
        self.check_nice_list_output(['a', 'b'])

    def test_list_to_line_break_string(self):
        input_data = set('ab')
        self.assertEqual(list_to_line_break_string(input_data), 'a\nb\n')

    def test_list_to_line_break_string_no_sort(self):
        input_data = ['b', 'a']
        self.assertEqual(list_to_line_break_string_no_sort(input_data), 'b\na\n')

    def test_nice_unix_time_stamp(self):
        input_data = 1459427460
        self.assertEqual(nice_unix_time(input_data), '2016-03-31 14:31:00', 'output not correct (int)')
        input_data = 1459427460.4
        self.assertEqual(nice_unix_time(input_data), '2016-03-31 14:31:00', 'output not correct (float)')
        self.assertEqual(nice_unix_time('test'), 'test')

    def test_sort_chart_list_by_value(self):
        test_list = [['a', 1], ['b', 2]]
        result = sort_chart_list_by_value(test_list)
        self.assertEqual(result, [['b', 2], ['a', 1]])

    def test_sort_chart_list_by_name(self):
        test_list = [['b', 2], ['a', 1]]
        result = sort_chart_list_by_name(test_list)
        self.assertEqual(result, [['a', 1], ['b', 2]])

    def test_text_highliter(self):
        self.assertEqual(text_highlighter('online'), '<span style="color:green;">online</span>')
        self.assertEqual(text_highlighter('offline'), '<span style="color:red;">offline</span>')
        self.assertEqual(text_highlighter('foo'), 'foo')
        self.assertEqual(text_highlighter('foo', green=['*']), '<span style="color:green;">foo</span>')
        self.assertEqual(text_highlighter('foo', red=['*']), '<span style="color:red;">foo</span>')

    def test_infection_color(self):
        assert 'color:green' in infection_color('clean')
        assert 'color:green' in infection_color(0)
        assert 'color:red' in infection_color('foo')
        assert 'color:red' in infection_color(9999)
        assert 'color:red' in infection_color(None)

    def test_fix_cwe_valid_string(self):
        self.assertEqual(fix_cwe("[CWE467] (Use of sizeof on a Pointer Type)"), "467")

    def test_fix_cwe_invalid_string(self):
        self.assertEqual(fix_cwe("something_really_strange"), "")


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
    ([1, 3], '<ul>\n\t<li>1</li>\n\t<li>3</li>\n</ul>\n'),
    ({'a': 1}, 'a: 1<br />'),
    (gmtime(0), '1970-01-01 - 00:00:00'),
    ('a_b', 'a b'),
    (gmtime, gmtime)
])
def test_generic_nice_representation(input_data, expected):
    assert generic_nice_representation(input_data) == expected


@pytest.mark.parametrize('tag_dict, output', [
    ({'a': 'danger'}, '<span class="label label-pill label-danger " style="font-size: 10px;">a</span>\n'),
    ({'a': 'danger', 'b': 'default'}, '<span class="label label-pill label-danger " style="font-size: 10px;">a</span>\n<span class="label label-pill label-default " style="font-size: 10px;">b</span>\n'),
    (None, '')
])
def test_render_tags(tag_dict, output):
    assert render_tags(tag_dict) == output


def test_empty_analysis_tags():
    assert render_analysis_tags(dict()) == ''


def test_render_analysis_tags_success():
    tags = {'such plugin': {'tag': {'color': 'very color', 'value': 'wow'}}}
    output = render_analysis_tags(tags)
    assert 'label-very color' in output
    assert '>wow<' in output


def test_render_analysis_tags_bad_type():
    tags = {'such plugin': {42: {'color': 'very color', 'value': 'wow'}}}
    with pytest.raises(AttributeError):
        render_analysis_tags(tags)


@pytest.mark.parametrize('score_and_class', [('low', 'active'), ('medium', 'warning'), ('high', 'danger')])
def test_vulnerability_class_success(score_and_class):
    assert vulnerability_class(score_and_class[0]) == score_and_class[1]


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
