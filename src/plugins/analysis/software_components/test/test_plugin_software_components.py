from pathlib import Path

import pytest

from ..code.software_components import AnalysisPlugin, _entry_has_no_trailing_version, get_version

YARA_TEST_FILE = Path(__file__).parent / 'data' / 'yara_test_file'


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
class TestAnalysisPluginsSoftwareComponents:
    def test_process_object(self, analysis_plugin):
        with YARA_TEST_FILE.open('rb') as fp:
            results = analysis_plugin.analyze(fp, {}, {})

        assert len(results.software_components) == 1, 'incorrect number of software components found'
        software_result = results.software_components[0]
        assert software_result.rule == 'MyTestRule', 'incorrect yara rule name'
        assert software_result.name == 'Test Software', 'incorrect software name from yara meta'
        assert software_result.website == 'http://www.fkie.fraunhofer.de', 'incorrect website from yara meta'
        assert software_result.description == 'This is a test rule', 'incorrect description from yara meta'
        assert software_result.open_source, 'incorrect open-source flag from yara meta'

        assert len(software_result.matching_strings) == 1, 'too many strings found'
        string_match = software_result.matching_strings[0]
        assert string_match.string == 'MyTestRule 0.1.3.', 'string not found'
        assert string_match.offset == 10
        assert string_match.identifier == '$a'
        assert '0.1.3' in software_result.versions, 'Version not detected'

        summary = analysis_plugin.summarize(results)
        assert len(summary) == 1, 'Number of summary results not correct'
        assert 'Test Software 0.1.3' in summary

    @pytest.mark.parametrize(
        ('version', 'expected_output', 'meta_dict'),
        [
            ('', None, {}),
            ('Foo 15.14.13', '15.14.13', {}),
            ('Foo 1.0', '1.0', {}),
            ('Foo 1.1.1b', '1.1.1b', {}),
            ('Foo', None, {}),
            ('Foo 01.02.03', '1.2.3', {}),
            ('Foo 00.1.', '0.1', {}),
            ('\x001.22.333\x00', '1.22.333', {}),
            ('Foo 03.02.01abc', '3.2.1a', {}),
            ('OpenSSH_9.6p1', '9.6p1', {}),
            ('OpenSSL 1.1.0i', '1.1.0i', {}),
            ('OpenSSL 0.9.8zh', '0.9.8zh', {'version_regex': '\\d\\.\\d\\.\\d[a-z]{0,2}'}),
            ('Foo v1.2.3', 'v1.2.3', {'version_regex': 'v?\\d\\.\\d\\.\\d'}),
            ('Bar a.b', 'a.b', {'version_regex': '[a-z]\\.[a-z]'}),
            ('524', '5.24', {'version_regex': r'\d{3}', '_sub_regex': '(\\d)(\\d{2})', '_sub_replacement': '\\1.\\2'}),
        ],
    )
    def test_get_version(self, analysis_plugin, version, expected_output, meta_dict):
        assert get_version(version, meta_dict) == expected_output, f'{version} not found correctly'

    def test_get_version_from_meta(self, analysis_plugin):
        version = 'v15.14.1a'
        assert (
            get_version(f'Foo {version}', {'version_regex': 'v\\d\\d\\.\\d\\d\\.\\d[a-z]'}) == version
        ), 'version not found correctly'

    def test_entry_has_no_trailing_version(self, analysis_plugin):
        assert not _entry_has_no_trailing_version('Linux', 'Linux 4.15.0-22')
        assert _entry_has_no_trailing_version('Linux', 'Linux')
        assert _entry_has_no_trailing_version(' Linux', 'Linux ')

    def test_get_tags(self, analysis_plugin):
        assert analysis_plugin.get_tags({}, ['OpenSSL']) == []
        tags = analysis_plugin.get_tags({}, ['Linux Kernel'])
        assert tags != []
        assert tags[0].value == 'Linux Kernel'
