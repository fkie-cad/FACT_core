import os
import itertools
from pathlib import Path
from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest
from objects.file import FileObject

from ..code.elf_analysis import AnalysisPlugin


TEST_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')


class test_analysis_plugin_elf_analysis(AnalysisPluginTest):

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

    def test_plugin(self):
        # self.check_unpacking_of_standard_unpack_set(os.path.join(TEST_DATA_DIR, 'cramfs.img'))
        print(os.path.join(TEST_DATA_DIR, 'hello'))
        test_object = FileObject(file_path=str(Path(TEST_DATA_DIR) / 'hello'))
        test_object.processed_analysis['file_type'] = {'mime': 'application/x-executable'}
        self.analysis_plugin.process_object(test_object)

        self.assertNotEqual(test_object.processed_analysis[self.PLUGIN_NAME]['Output'], {})
        self.assertEqual(sorted(test_object.processed_analysis[self.PLUGIN_NAME]['summary']), ['dynamic_entries', 'header', 'sections', 'segments'])
