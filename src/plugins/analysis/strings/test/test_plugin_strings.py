# pylint: disable=protected-access
import os

import pytest
from common_helper_files import get_dir_of_file

from objects.file import FileObject
from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest  # pylint: disable=wrong-import-order

from ..code.strings import AnalysisPlugin

TEST_DATA_DIR = os.path.join(get_dir_of_file(__file__), 'data')


@pytest.mark.cfg_defaults(
    {
        'printable_strings': {
            'min-length': '4',
        }
    },
)
class TestAnalysisPlugInPrintableStrings(AnalysisPluginTest):
    PLUGIN_NAME = 'printable_strings'
    PLUGIN_CLASS = AnalysisPlugin

    def setUp(self):
        super().setUp()
        self.strings = ['first string', 'second<>_$tring!', 'third:?-+012345/\\string']
        self.offsets = [(3, self.strings[0]), (21, self.strings[1]), (61, self.strings[2])]

    def _set_config(self):
        self.config.set(self.PLUGIN_NAME, 'min-length', '4')

    def test_process_object(self):
        fo = FileObject(file_path=os.path.join(TEST_DATA_DIR, 'string_find_test_file2'))
        fo = self.analysis_plugin.process_object(fo)
        results = fo.processed_analysis[self.PLUGIN_NAME]
        for item in self.strings:
            self.assertIn(item, results['strings'], f'{item} not found')
        self.assertEqual(len(results['strings']), len(self.strings), 'number of found strings not correct')
        for item in self.offsets:
            assert item in results['offsets'], f'offset {item} not found'
        assert len(results['offsets']) == len(self.offsets), 'number of offsets not correct'

    def test_process_object__no_strings(self):
        fo = FileObject(file_path=os.path.join(TEST_DATA_DIR, 'string_find_test_file_no_strings'))
        fo = self.analysis_plugin.process_object(fo)
        results = fo.processed_analysis[self.PLUGIN_NAME]
        self.assertIn('strings', results)
        self.assertIn('offsets', results)
        self.assertEqual(len(results['strings']), 0, 'number of found strings not correct')
        self.assertEqual(len(results['offsets']), 0, 'number of offsets not correct')

    def test_match_with_offset(self):
        regex = self.analysis_plugin.regexes[0][0]
        for test_input, expected_output in [
            (b'\xffabcdefghij\xff', [(1, 'abcdefghij')]),
            (b'!"$%&/()=?+*#-.,\t\n\r', [(0, '!"$%&/()=?+*#-.,\t\n\r')]),
            (b'\xff\xffabc\xff\xff', []),
            (b'abcdefghij\xff1234567890', [(0, 'abcdefghij'), (11, '1234567890')]),
        ]:
            result = AnalysisPlugin._match_with_offset(regex, test_input)
            assert result == expected_output

    def test_match_with_offset__16bit(self):
        regex, encoding = self.analysis_plugin.regexes[1]
        test_input = b'01234a\0b\0c\0d\0e\0f\0g\0h\0i\0j\x0005678'
        result = AnalysisPlugin._match_with_offset(regex, test_input, encoding)
        assert result == [(5, 'abcdefghij')]
