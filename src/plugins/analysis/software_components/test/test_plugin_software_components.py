import os

from common_helper_files import get_dir_of_file

from objects.file import FileObject
from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest  # pylint: disable=wrong-import-order

from ..code.software_components import AnalysisPlugin

TEST_DATA_DIR = os.path.join(get_dir_of_file(__file__), 'data')


class TestAnalysisPluginsSoftwareComponents(AnalysisPluginTest):

    PLUGIN_NAME = 'software_components'
    PLUGIN_CLASS = AnalysisPlugin

    def test_process_object(self):
        test_file = FileObject(file_path=os.path.join(TEST_DATA_DIR, 'yara_test_file'))
        processed_file = self.analysis_plugin.process_object(test_file)
        results = processed_file.processed_analysis[self.PLUGIN_NAME]
        self.assertEqual(len(results), 2, 'incorrect number of software components found')
        self.assertTrue('MyTestRule' in results, 'test Rule match not found')
        self.assertEqual(
            results['MyTestRule']['meta']['software_name'], 'Test Software', 'incorrect software name from yara meta',
        )
        self.assertEqual(
            results['MyTestRule']['meta']['website'],
            'http://www.fkie.fraunhofer.de',
            'incorrect website from yara meta',
        )
        self.assertEqual(
            results['MyTestRule']['meta']['description'], 'This is a test rule', 'incorrect description from yara meta',
        )
        self.assertTrue(results['MyTestRule']['meta']['open_source'], 'incorrect open-source flag from yara meta')
        self.assertTrue((10, '$a', 'MyTestRule 0.1.3.') in results['MyTestRule']['strings'], 'string not found')
        self.assertTrue('0.1.3' in results['MyTestRule']['meta']['version'], 'Version not detected')
        self.assertEqual(len(results['MyTestRule']['strings']), 1, 'to much strings found')
        self.assertEqual(len(results['summary']), 1, 'Number of summary results not correct')
        self.assertIn('Test Software 0.1.3', results['summary'])

    def check_version(self, input_string, version):
        self.assertEqual(self.analysis_plugin.get_version(input_string, {}), version, f'{version} not found correctly')

    def test_get_version(self):
        self.check_version('Foo 15.14.13', '15.14.13')
        self.check_version('Foo 0.1.0', '0.1.0')
        self.check_version('Foo 1.1.1b', '1.1.1b')
        self.check_version('Foo', '')
        self.check_version('Foo 01.02.03', '1.2.3')
        self.check_version('Foo 00.1.', '0.1')
        self.check_version('\x001.22.333\x00', '1.22.333')

    def test_get_version_from_meta(self):
        version = 'v15.14.1a'
        self.assertEqual(
            self.analysis_plugin.get_version(f'Foo {version}', {'version_regex': 'v\\d\\d\\.\\d\\d\\.\\d[a-z]'}),
            version,
            'version not found correctly',
        )

    def test_entry_has_no_trailing_version(self):
        # pylint: disable=protected-access
        assert not self.analysis_plugin._entry_has_no_trailing_version('Linux', 'Linux 4.15.0-22')
        assert self.analysis_plugin._entry_has_no_trailing_version('Linux', 'Linux')
        assert self.analysis_plugin._entry_has_no_trailing_version(' Linux', 'Linux ')

    def test_add_os_key_fail(self):
        test_file = FileObject(file_path=os.path.join(TEST_DATA_DIR, 'yara_test_file'))
        with self.assertRaises(KeyError):
            self.analysis_plugin.add_os_key(test_file)

        test_file.processed_analysis[self.PLUGIN_NAME] = dict(summary=['OpenSSL'])
        self.analysis_plugin.add_os_key(test_file)
        assert 'tags' not in test_file.processed_analysis[self.PLUGIN_NAME]

    def test_add_os_key_success(self):
        test_file = FileObject(file_path=os.path.join(TEST_DATA_DIR, 'yara_test_file'))
        test_file.processed_analysis[self.PLUGIN_NAME] = dict(summary=['Linux Kernel'])
        self.analysis_plugin.add_os_key(test_file)
        assert 'tags' in test_file.processed_analysis[self.PLUGIN_NAME]
        assert test_file.processed_analysis[self.PLUGIN_NAME]['tags']['OS']['value'] == 'Linux Kernel'

    def test_update_os_key(self):
        test_file = FileObject(file_path=os.path.join(TEST_DATA_DIR, 'yara_test_file'))
        test_file.processed_analysis[self.PLUGIN_NAME] = dict(
            summary=['Linux Kernel'], tags={'OS': {
                'value': 'Fire OS'
            }},
        )

        assert test_file.processed_analysis[self.PLUGIN_NAME]['tags']['OS']['value'] == 'Fire OS'
        self.analysis_plugin.add_os_key(test_file)
        assert test_file.processed_analysis[self.PLUGIN_NAME]['tags']['OS']['value'] == 'Linux Kernel'
