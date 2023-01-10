import os

import pytest
from common_helper_files import get_dir_of_file

from objects.file import FileObject

from ..code.software_components import AnalysisPlugin

TEST_DATA_DIR = os.path.join(get_dir_of_file(__file__), 'data')


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
class TestAnalysisPluginsSoftwareComponents:
    def test_process_object(self, analysis_plugin):
        test_file = FileObject(file_path=os.path.join(TEST_DATA_DIR, 'yara_test_file'))

        processed_file = analysis_plugin.process_object(test_file)
        results = processed_file.processed_analysis[analysis_plugin.NAME]
        assert len(results) == 2, 'incorrect number of software components found'
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

    def check_version(self, analysis_plugin, input_string, version):
        assert analysis_plugin.get_version(input_string, {}) == version, f'{version} not found correctly'

    def test_get_version(self, analysis_plugin):
        self.check_version(analysis_plugin, 'Foo 15.14.13', '15.14.13')
        self.check_version(analysis_plugin, 'Foo 1.0', '1.0')
        self.check_version(analysis_plugin, 'Foo 1.1.1b', '1.1.1b')
        self.check_version(analysis_plugin, 'Foo', '')
        self.check_version(analysis_plugin, 'Foo 01.02.03', '1.2.3')
        self.check_version(analysis_plugin, 'Foo 00.1.', '0.1')
        self.check_version(analysis_plugin, '\x001.22.333\x00', '1.22.333')

    def test_get_version_from_meta(self, analysis_plugin):
        version = 'v15.14.1a'
        assert (
            analysis_plugin.get_version(f'Foo {version}', {'version_regex': 'v\\d\\d\\.\\d\\d\\.\\d[a-z]'}) == version
        ), 'version not found correctly'

    def test_entry_has_no_trailing_version(self, analysis_plugin):
        # pylint: disable=protected-access
        assert not analysis_plugin._entry_has_no_trailing_version('Linux', 'Linux 4.15.0-22')
        assert analysis_plugin._entry_has_no_trailing_version('Linux', 'Linux')
        assert analysis_plugin._entry_has_no_trailing_version(' Linux', 'Linux ')

    def test_add_os_key_fail(self, analysis_plugin):
        test_file = FileObject(file_path=os.path.join(TEST_DATA_DIR, 'yara_test_file'))
        with pytest.raises(KeyError):
            analysis_plugin.add_os_key(test_file)

        test_file.processed_analysis[analysis_plugin.NAME] = dict(summary=['OpenSSL'])
        analysis_plugin.add_os_key(test_file)
        assert 'tags' not in test_file.processed_analysis[analysis_plugin.NAME]

    def test_add_os_key_success(self, analysis_plugin):
        test_file = FileObject(file_path=os.path.join(TEST_DATA_DIR, 'yara_test_file'))
        test_file.processed_analysis[analysis_plugin.NAME] = dict(summary=['Linux Kernel'])
        analysis_plugin.add_os_key(test_file)
        assert 'tags' in test_file.processed_analysis[analysis_plugin.NAME]
        assert test_file.processed_analysis[analysis_plugin.NAME]['tags']['OS']['value'] == 'Linux Kernel'

    def test_update_os_key(self, analysis_plugin):
        test_file = FileObject(file_path=os.path.join(TEST_DATA_DIR, 'yara_test_file'))

        test_file.processed_analysis[analysis_plugin.NAME] = dict(
            summary=['Linux Kernel'], tags={'OS': {'value': 'Fire OS'}}
        )

        assert test_file.processed_analysis[analysis_plugin.NAME]['tags']['OS']['value'] == 'Fire OS'
        analysis_plugin.add_os_key(test_file)
        assert test_file.processed_analysis[analysis_plugin.NAME]['tags']['OS']['value'] == 'Linux Kernel'
