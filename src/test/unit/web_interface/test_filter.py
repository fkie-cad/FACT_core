import unittest
import pytest
from time import gmtime

from web_interface.filter import replace_underscore_filter, byte_number_filter, get_all_uids_in_string, nice_list, uids_to_link, \
    list_to_line_break_string, nice_unix_time, nice_number_filter, sort_chart_list_by_value, \
    sort_chart_list_by_name, text_highlighter, generic_nice_representation, list_to_line_break_string_no_sort,\
    encode_base64_filter, render_tags


class TestWebInterfaceFilter(unittest.TestCase):

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
