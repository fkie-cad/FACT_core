import os

from analysis.YaraPluginBase import YaraBasePlugin
from helperFunctions.fileSystem import get_src_dir
from objects.file import FileObject
from test.common_helper import get_test_data_dir
from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest


class TestAnalysisYaraBasePlugin(AnalysisPluginTest):

    PLUGIN_NAME = "Yara_Base_Plugin"

    def setUp(self):
        super().setUp()
        config = self.init_basic_config()
        self.intended_signature_path = os.path.join(get_src_dir(), 'analysis/signatures', self.PLUGIN_NAME)
        self.analysis_plugin = YaraBasePlugin(self, config=config, plugin_path='/foo/bar/Yara_Base_Plugin/code/test.py')

    def test_get_signature_file_name(self):
        assert self.analysis_plugin._get_signature_file_name('/foo/bar/plugin_name/code/test.py') == 'plugin_name.yc'

    def test_get_signature_paths(self):
        self.assertTrue(isinstance(self.analysis_plugin.signature_path, str), "incorrect type")
        self.assertEqual('{}.yc'.format(self.intended_signature_path.rstrip('/')), self.analysis_plugin.signature_path, "signature path is wrong")

    def test_process_object(self):
        test_file = FileObject(file_path=os.path.join(get_test_data_dir(), "yara_test_file"))
        test_file.processed_analysis.update({self.PLUGIN_NAME: []})
        processed_file = self.analysis_plugin.process_object(test_file)
        results = processed_file.processed_analysis[self.PLUGIN_NAME]
        self.assertEqual(len(results), 2, "not all matches found")
        self.assertTrue('testRule' in results, "testRule match not found")
        self.assertEqual(results['summary'], ['testRule'])

    def test_process_object_nothing_found(self):
        test_file = FileObject(file_path=os.path.join(get_test_data_dir(), "zero_byte"))
        test_file.processed_analysis.update({self.PLUGIN_NAME: []})
        processed_file = self.analysis_plugin.process_object(test_file)
        self.assertEqual(len(processed_file.processed_analysis[self.PLUGIN_NAME]), 1, "result present but should not")
        self.assertEqual(processed_file.processed_analysis[self.PLUGIN_NAME]['summary'], [], "summary not empty")

    def test_new_yara_matching(self):
        with open(os.path.join(get_test_data_dir(), 'yara_matches'), 'r') as fd:
            match_file = fd.read()
        matches = self.analysis_plugin._parse_yara_output(match_file)

        self.assertIsInstance(matches, dict, 'matches should be dict')
        self.assertIn('PgpPublicKeyBlock', matches.keys(), 'Pgp block should have been matched')
        self.assertIn(0, matches['PgpPublicKeyBlock']['strings'][0], 'first block should start at 0x0')
