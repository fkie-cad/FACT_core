from pathlib import Path

import pytest

from objects.file import FileObject

from ..code.software_components import AnalysisPlugin

YARA_TEST_FILE = str(Path(__file__).parent / 'data' / 'yara_test_file')


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
class TestAnalysisPluginsSoftwareComponents:
    def test_process_object(self, analysis_plugin):
        test_file = FileObject(file_path=YARA_TEST_FILE)

        processed_file = analysis_plugin.process_object(test_file)
        results = processed_file.processed_analysis[analysis_plugin.NAME]
        assert len(results) == 2, 'incorrect number of software components found'  # noqa: PLR2004
        assert 'MyTestRule' in results, 'test Rule match not found'
        assert (
            results['MyTestRule']['meta']['software_name'] == 'Test Software'
        ), 'incorrect software name from yara meta'
        assert (
            results['MyTestRule']['meta']['website'] == 'http://www.fkie.fraunhofer.de'
        ), 'incorrect website from yara meta'
        assert (
            results['MyTestRule']['meta']['description'] == 'This is a test rule'
        ), 'incorrect description from yara meta'
        assert results['MyTestRule']['meta']['open_source'], 'incorrect open-source flag from yara meta'
        assert (10, '$a', 'MyTestRule 0.1.3.') in results['MyTestRule']['strings'], 'string not found'
        assert '0.1.3' in results['MyTestRule']['meta']['version'], 'Version not detected'
        assert len(results['MyTestRule']['strings']) == 1, 'to much strings found'
        assert len(results['summary']) == 1, 'Number of summary results not correct'
        assert 'Test Software 0.1.3' in results['summary']

    @pytest.mark.parametrize(
        ('version', 'expected_output', 'meta_dict'),
        [
            ('', '', {}),
            ('Foo 15.14.13', '15.14.13', {}),
            ('Foo 1.0', '1.0', {}),
            ('Foo 1.1.1b', '1.1.1b', {}),
            ('Foo', '', {}),
            ('Foo 01.02.03', '1.2.3', {}),
            ('Foo 00.1.', '0.1', {}),
            ('\x001.22.333\x00', '1.22.333', {}),
            ('Foo 03.02.01abc', '3.2.1a', {}),
            ('OpenSSL 1.1.0i', '1.1.0i', {}),
            ('OpenSSL 0.9.8zh', '0.9.8zh', {'version_regex': '\\d\\.\\d\\.\\d[a-z]{0,2}'}),
            ('Foo v1.2.3', 'v1.2.3', {'version_regex': 'v?\\d\\.\\d\\.\\d'}),
            ('Bar a.b', 'a.b', {'version_regex': '[a-z]\\.[a-z]'}),
        ],
    )
    def test_get_version(self, analysis_plugin, version, expected_output, meta_dict):
        assert analysis_plugin.get_version(version, meta_dict) == expected_output, f'{version} not found correctly'

    def test_get_version_from_meta(self, analysis_plugin):
        version = 'v15.14.1a'
        assert (
            analysis_plugin.get_version(f'Foo {version}', {'version_regex': 'v\\d\\d\\.\\d\\d\\.\\d[a-z]'}) == version
        ), 'version not found correctly'

    def test_entry_has_no_trailing_version(self, analysis_plugin):
        assert not analysis_plugin._entry_has_no_trailing_version('Linux', 'Linux 4.15.0-22')
        assert analysis_plugin._entry_has_no_trailing_version('Linux', 'Linux')
        assert analysis_plugin._entry_has_no_trailing_version(' Linux', 'Linux ')

    def test_add_os_key_fail(self, analysis_plugin):
        test_file = FileObject(file_path=YARA_TEST_FILE)
        with pytest.raises(KeyError):
            analysis_plugin.add_os_key(test_file)

        test_file.processed_analysis[analysis_plugin.NAME] = {'summary': ['OpenSSL']}
        analysis_plugin.add_os_key(test_file)
        assert 'tags' not in test_file.processed_analysis[analysis_plugin.NAME]

    def test_add_os_key_success(self, analysis_plugin):
        test_file = FileObject(file_path=YARA_TEST_FILE)
        test_file.processed_analysis[analysis_plugin.NAME] = {'summary': ['Linux Kernel']}
        analysis_plugin.add_os_key(test_file)
        assert 'tags' in test_file.processed_analysis[analysis_plugin.NAME]
        assert test_file.processed_analysis[analysis_plugin.NAME]['tags']['OS']['value'] == 'Linux Kernel'

    def test_update_os_key(self, analysis_plugin):
        test_file = FileObject(file_path=YARA_TEST_FILE)

        test_file.processed_analysis[analysis_plugin.NAME] = {
            'summary': ['Linux Kernel'],
            'tags': {'OS': {'value': 'Fire OS'}},
        }

        assert test_file.processed_analysis[analysis_plugin.NAME]['tags']['OS']['value'] == 'Fire OS'
        analysis_plugin.add_os_key(test_file)
        assert test_file.processed_analysis[analysis_plugin.NAME]['tags']['OS']['value'] == 'Linux Kernel'
