from pathlib import Path

from objects.file import FileObject
from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest

from ..code.device_tree import AnalysisPlugin

TEST_DATA = Path(__file__).parent.parent / 'test/data'


class test_device_tree(AnalysisPluginTest):

    PLUGIN_NAME = 'device_tree'

    def setUp(self):
        super().setUp()
        config = self.init_basic_config()

        self.analysis_plugin = AnalysisPlugin(self, config=config)
        self.test_file = TEST_DATA / 'device_tree.dtb'

    def tearDown(self):
        super().tearDown()
        # additional tearDown can go here

    def test_process_object(self):
        test_object = FileObject()
        test_object.file_path = str(self.test_file)
        result = self.analysis_plugin.process_object(test_object)

        assert result.processed_analysis[self.PLUGIN_NAME]['summary'] == ['device tree found']

    def test_execute_device_tree_compiler(self):
        test_object = self.test_file
        result = self.analysis_plugin.execute_device_tree_compiler(test_object)

        assert '#address-cells = <0x01>;' in result
