from flask import Markup

from test.unit.compare.compare_plugin_test_class import ComparePluginTest  # pylint: disable=wrong-import-order

from ..code.file_header import ComparePlugin, replace_none_ascii_with_dots


class TestComparePluginFileHeader(ComparePluginTest):
    PLUGIN_NAME = 'File_Header'

    def setup_plugin(self):
        return ComparePlugin(self, config=self.config, plugin_path=None)

    def test_compare(self):
        result = self.c_plugin.compare_function([self.fw_one, self.fw_two, self.fw_three])

        assert all(key in result for key in ['hexdiff', 'ascii', 'offsets']), 'not all result keys given'
        assert all(isinstance(result[key], Markup) for key in ['hexdiff', 'ascii', 'offsets']), 'partial results should be flask.Markup strings'

        assert '>4B<' in result['hexdiff'], 'no bytes in hexdump or bad upper case conversion'
        assert '<br />' in result['hexdiff'], 'no linebreaks found'

    def test_at_least_two_are_common(self):
        should_be_true = [3, 2, 1, 2]
        should_be_false = [5, 4, 3, 1, 2, 6]
        assert self.c_plugin._at_least_two_are_common(should_be_true), 'should find a commonality'  # pylint: disable=no-member,protected-access
        assert not self.c_plugin._at_least_two_are_common(should_be_false), 'should not find a commonality'  # pylint: disable=no-member,protected-access


def test_process_ascii_bytes():
    input_bytes = b'GoodCharacters\xBA\xDCharacters'
    expected_output = 'GoodCharacters..haracters'

    assert len(replace_none_ascii_with_dots(input_bytes)) == len(input_bytes), 'length of strings do not match'
    assert replace_none_ascii_with_dots(input_bytes).decode() == expected_output, 'ascii byte processing not correct'
