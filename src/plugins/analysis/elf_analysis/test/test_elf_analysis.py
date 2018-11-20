import os
import itertools
from pathlib import Path
from unittest.mock import patch

from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest
from objects.file import FileObject

from ..code.elf_analysis import AnalysisPlugin


TEST_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')


class TestAnalysisPluginElfAnalysis(AnalysisPluginTest):

    PLUGIN_NAME = 'elf_analysis'

    def setUp(self):
        super().setUp()
        config = self.init_basic_config()
        # additional config can go here
        # additional setup can go here
        self.analysis_plugin = AnalysisPlugin(self, config=config)

    def tearDown(self):
        super().tearDown()
        # additional tearDown can go here

    # TODO @patch('lief.parse', lambda x: None)
    # TODO @patch('lief.to_json_from_abstract', lambda x: global_var_expected_json_dict)
    def test_plugin(self):
        test_object = FileObject(file_path=str(Path(TEST_DATA_DIR) / 'test_binary'))
        test_object.processed_analysis['file_type'] = {'mime': 'application/x-executable'}
        self.analysis_plugin.process_object(test_object)

        self.assertNotEqual(test_object.processed_analysis[self.PLUGIN_NAME]['Output'], {})
        self.assertEqual(sorted(test_object.processed_analysis[self.PLUGIN_NAME]['summary']), ['dynamic_entries', 'exported_functions', 'header', 'imported_functions', 'sections', 'segments'])
