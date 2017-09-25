from common_helper_files import get_dir_of_file
import os

from objects.file import FileObject
from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest

from ..code.software_components import AnalysisPlugin


TEST_DATA_DIR = os.path.join(get_dir_of_file(__file__), 'data')


class Test_analysis_plugins_software_components(AnalysisPluginTest):

    PLUGIN_NAME = 'software_components'

    def setUp(self):
        super().setUp()
        config = self.init_basic_config()
        self.analysis_plugin = AnalysisPlugin(self, config=config)

    def test_process_object(self):
        test_file = FileObject(file_path=os.path.join(TEST_DATA_DIR, 'yara_test_file'))
        processed_file = self.analysis_plugin.process_object(test_file)
        results = processed_file.processed_analysis[self.PLUGIN_NAME]
        self.assertEqual(len(results), 2, 'incorrect number of software components found')
        self.assertTrue('MyTestRule' in results, 'test Rule match not found')
        self.assertEqual(results['MyTestRule']['meta']['software_name'], 'Test Software', 'incorrect software name from yara meta')
        self.assertEqual(results['MyTestRule']['meta']['website'], 'http://www.fkie.fraunhofer.de', 'incorrect website from yara meta')
        self.assertEqual(results['MyTestRule']['meta']['description'], 'This is a test rule', 'incorrect description from yara meta')
        self.assertTrue(results['MyTestRule']['meta']['open_source'], 'incorrect open-source flag from yara meta')
        self.assertTrue((10, '$a', b'MyTestRule 0.1.3.') in results['MyTestRule']['strings'], 'string not found')
        self.assertTrue('0.1.3' in results['MyTestRule']['meta']['version'], 'Version not detected')
        self.assertEqual(len(results['MyTestRule']['strings']), 1, 'to much strings found')
        self.assertEqual(len(results['summary']), 1, 'Number of summary results not correct')
        self.assertIn('Test Software 0.1.3', results['summary'])

    def check_version(self, input_string, version):
        self.assertEqual(self.analysis_plugin.get_version(input_string), version, '{} not found correctly'.format(version))

    def test_get_version(self):
        self.check_version('Foo 15.14.13', '15.14.13')
        self.check_version('Foo 1.0', '1.0')
        self.check_version('Foo 1.1.1b', '1.1.1b')
        self.check_version('Foo', '')
