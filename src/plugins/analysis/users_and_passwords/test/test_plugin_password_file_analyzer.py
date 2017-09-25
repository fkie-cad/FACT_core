import os

from common_helper_files import get_dir_of_file

from objects.file import FileObject
from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest
from ..code.password_file_analyzer import AnalysisPlugin

TEST_DATA_DIR = os.path.join(get_dir_of_file(__file__), 'data')


class TestAnalysisPluginPasswordFileAnalyzer(AnalysisPluginTest):

    PLUGIN_NAME = 'users_and_passwords'

    def setUp(self):
        super().setUp()
        config = self.init_basic_config()
        self.analysis_plugin = AnalysisPlugin(self, config=config)

    def test_process_object(self):
        test_file = FileObject(file_path=os.path.join(TEST_DATA_DIR, 'passwd_test'))
        processed_object = self.analysis_plugin.process_object(test_file)
        results = processed_object.processed_analysis[self.PLUGIN_NAME]

        self.assertEqual(len(results), 7)
        for s in ['vboxadd', 'mongodb', 'clamav', 'pulse', 'johndoe', 'max']:
            self.assertIn(s, results)
            self.assertIn(s, results['summary'])
        self.assertIn('password-hash', results['max'])
        self.assertIn('password', results['max'])
        self.assertEqual(results['max']['password'], 'dragon')
        self.assertIn('password-hash', results['johndoe'])
        self.assertIn('password', results['johndoe'])
        self.assertEqual(results['johndoe']['password'], '123456')

        test_file = FileObject(file_path=os.path.join(TEST_DATA_DIR, 'passwd.bin'))
        processed_object = self.analysis_plugin.process_object(test_file)
        results = processed_object.processed_analysis[self.PLUGIN_NAME]

        self.assertEqual(len(results), 3)
        for s in ['johndoe', 'max']:
            self.assertIn(s, results)
            self.assertIn(s, results['summary'])
        self.assertIn('password-hash', results['johndoe'])
        self.assertIn('password', results['johndoe'])
        self.assertEqual(results['johndoe']['password'], '123456')
        self.assertIn('password-hash', results['max'])
        self.assertIn('password', results['max'])
        self.assertEqual(results['max']['password'], 'dragon')
