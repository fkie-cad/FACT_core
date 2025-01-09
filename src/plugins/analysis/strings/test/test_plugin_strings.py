from __future__ import annotations

from pathlib import Path

import pytest

from ..code.strings import AnalysisPlugin

TEST_DATA_DIR = Path(__file__).parent / 'data'


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
    strings = ('first string', 'second<>_$tring!', 'third:?-+012345/\\string')
    offsets = ((3, strings[0]), (21, strings[1]), (61, strings[2]))

    def test_process_object(self, analysis_plugin):
        with (TEST_DATA_DIR / 'string_find_test_file2').open('rb') as fp:
            results = analysis_plugin.analyze(fp, {}, {})
        assert {s.string for s in results.strings} == set(self.strings)
        assert {(s.offset, s.string) for s in results.strings} == set(self.offsets)
        assert len(results.strings) == len(self.offsets), 'number of results not correct'

    def test_process_object__no_strings(self, analysis_plugin):
        with (TEST_DATA_DIR / 'string_find_test_file_no_strings').open('rb') as fp:
            results = analysis_plugin.analyze(fp, {}, {})
        assert len(results.strings) == 0, 'number of found strings not correct'

    def test_match_with_offset(self, analysis_plugin):
        regex = analysis_plugin.regexes[0][0]
        for test_input, expected_output in [
            (b'\xffabcdefghij\xff', [(1, 'abcdefghij')]),
            (b'!"$%&/()=?+*#-.,\t\n\r', [(0, '!"$%&/()=?+*#-.,\t\n\r')]),
            (b'\xff\xffabc\xff\xff', []),
            (b'abcdefghij\xff1234567890', [(0, 'abcdefghij'), (11, '1234567890')]),
        ]:
            result = list(AnalysisPlugin._match_with_offset(regex, test_input))
            assert result == expected_output

    def test_match_with_offset__16bit(self, analysis_plugin):
        regex, encoding = analysis_plugin.regexes[1]
        test_input = b'01234a\0b\0c\0d\0e\0f\0g\0h\0i\0j\x0005678'
        result = list(AnalysisPlugin._match_with_offset(regex, test_input, encoding))
        assert result == [(5, 'abcdefghij')]
