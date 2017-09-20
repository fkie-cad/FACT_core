import unittest

from web_interface.filter import replace_underscore_filter, byte_number_filter, get_all_uids_in_string, nice_list, uids_to_link, \
    list_to_line_break_string, nice_unix_time, nice_number_filter, sort_chart_list_by_value, \
    sort_chart_list_by_name, text_highlighter, generic_nice_representation, list_to_line_break_string_no_sort


class TestWebInterfaceFilter(unittest.TestCase):

    def test_byte_number_filter(self):
        self.assertEqual(byte_number_filter(1000), '1000.00 Byte', 'bytes output not correct')
        self.assertEqual(byte_number_filter(1024), '1.00 KiB', 'KB output not correct')
        self.assertEqual(byte_number_filter(1024 * 1024), '1.00 MiB', 'MB output not correct')
        # verbose
        self.assertEqual(byte_number_filter(1000, verbose=True), '1000.00 Byte (1,000 bytes)', 'verbose byte output not correct')

    def test_replace_underscore(self):
        a = 'test_string'
        self.assertEqual(replace_underscore_filter(a), 'test string', 'output not correct')

    def test_get_all_uids_in_string(self):
        test_string = '{"d41c0f1431b39b9db565b4e32a5437c61c77762a3f4401bac3bafa4887164117_24", "f7c927fb0c209035c7e6939bdd00eabdaada429f2ee9aeca41290412c8c79759_25" , "deaa23651f0a9cc247a20d0e0a78041a8e40b144e21b82081ecb519dd548eecf_24494080"}'
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

    def test_nice_number(self):
        self.assertEqual(nice_number_filter(123), '123')
        self.assertEqual(nice_number_filter(1234), '1,234')
        self.assertEqual(nice_number_filter(1234.1234), '1,234.12')
        self.assertEqual(nice_number_filter(None), 'not available')

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

    def test_generic_nice_representation(self):
        self.assertEqual(generic_nice_representation(b'abc'), 'abc', 'byte rep not correct')
        self.assertEqual(generic_nice_representation(1234), '1,234', 'int rep not correct')
        self.assertIsInstance(generic_nice_representation([1, 3]), str, 'list not converted to string')
        self.assertIsInstance(generic_nice_representation({'a': 1}), str, 'dict not converted to string')
