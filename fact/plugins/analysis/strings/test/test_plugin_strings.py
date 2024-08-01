import os

import pytest
from common_helper_files import get_dir_of_file

from fact.objects.file import FileObject

from ..code.strings import AnalysisPlugin

TEST_DATA_DIR = os.path.join(get_dir_of_file(__file__), 'data')  # noqa: PTH118


@pytest.mark.backend_config_overwrite(
    {
        'plugin': {
            'printable_strings': {
                'name': 'printable_strings',
                'min-length': '4',
            }
        }
    },
)
@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
class TestAnalysisPlugInPrintableStrings:
    strings = ['first string', 'second<>_$tring!', 'third:?-+012345/\\string']  # noqa: RUF012
    offsets = [(3, strings[0]), (21, strings[1]), (61, strings[2])]  # noqa: RUF012

    def test_process_object(self, analysis_plugin):
        fo = FileObject(file_path=os.path.join(TEST_DATA_DIR, 'string_find_test_file2'))  # noqa: PTH118
        fo = analysis_plugin.process_object(fo)
        results = fo.processed_analysis[analysis_plugin.NAME]
        for item in self.strings:
            assert item in results['strings'], f'{item} not found'
        assert len(results['strings']) == len(self.strings), 'number of found strings not correct'
        for item in self.offsets:
            assert item in results['offsets'], f'offset {item} not found'
        assert len(results['offsets']) == len(self.offsets), 'number of offsets not correct'

    def test_process_object__no_strings(self, analysis_plugin):
        fo = FileObject(file_path=os.path.join(TEST_DATA_DIR, 'string_find_test_file_no_strings'))  # noqa: PTH118
        fo = analysis_plugin.process_object(fo)
        results = fo.processed_analysis[analysis_plugin.NAME]
        assert 'strings' in results
        assert 'offsets' in results
        assert len(results['strings']) == 0, 'number of found strings not correct'
        assert len(results['offsets']) == 0, 'number of offsets not correct'

    def test_match_with_offset(self, analysis_plugin):
        regex = analysis_plugin.regexes[0][0]
        for test_input, expected_output in [
            (b'\xffabcdefghij\xff', [(1, 'abcdefghij')]),
            (b'!"$%&/()=?+*#-.,\t\n\r', [(0, '!"$%&/()=?+*#-.,\t\n\r')]),
            (b'\xff\xffabc\xff\xff', []),
            (b'abcdefghij\xff1234567890', [(0, 'abcdefghij'), (11, '1234567890')]),
        ]:
            result = AnalysisPlugin._match_with_offset(regex, test_input)
            assert result == expected_output

    def test_match_with_offset__16bit(self, analysis_plugin):
        regex, encoding = analysis_plugin.regexes[1]
        test_input = b'01234a\0b\0c\0d\0e\0f\0g\0h\0i\0j\x0005678'
        result = AnalysisPlugin._match_with_offset(regex, test_input, encoding)
        assert result == [(5, 'abcdefghij')]
