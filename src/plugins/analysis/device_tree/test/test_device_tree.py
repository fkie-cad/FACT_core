from pathlib import Path

from objects.file import FileObject
from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest  # pylint: disable=wrong-import-order

from ..code.device_tree import AnalysisPlugin

TEST_DATA = Path(__file__).parent.parent / 'test/data'
TEST_FILE = TEST_DATA / 'device_tree.dtb'
EXPECTED_RESULT = 'model = "Manufac XYZ1234ABC";'


class TestDeviceTree(AnalysisPluginTest):

    PLUGIN_NAME = AnalysisPlugin.NAME

    def setUp(self):
        super().setUp()
        config = self.init_basic_config()

        self.analysis_plugin = AnalysisPlugin(self, config=config)

    def test_process_object(self):
        test_object = FileObject()
        test_object.processed_analysis['file_type'] = {'mime': 'linux/device-tree'}
        test_object.file_path = str(TEST_FILE)
        result = self.analysis_plugin.process_object(test_object)

        assert result.processed_analysis[self.PLUGIN_NAME]['summary'] == ['device tree found']


def test_convert_device_tree():
    result = AnalysisPlugin.convert_device_tree(TEST_FILE)

    assert EXPECTED_RESULT in result


def test_dump_device_tree():
    test_file = TEST_DATA / 'binary_file_containing_device_tree'
    result = AnalysisPlugin.dump_device_tree(test_file)

    assert EXPECTED_RESULT in result
