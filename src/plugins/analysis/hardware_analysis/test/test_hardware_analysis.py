from pathlib import Path

from objects.file import FileObject
from test.common_helper import get_test_data_dir  # pylint: disable=wrong-import-order
from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest  # pylint: disable=wrong-import-order

from ..code.hardware_analysis import AnalysisPlugin

TEST_DATA = Path(get_test_data_dir())


class TestHardwareAnalysis(AnalysisPluginTest):

    PLUGIN_NAME = 'hardware_analysis'
    PLUGIN_CLASS = AnalysisPlugin

    def test_cpu_architecture_found(self):
        test_object = FileObject()
        test_object.processed_analysis['cpu_architecture'] = {'summary': ['ARM']}
        result = self.analysis_plugin.cpu_architecture_analysis(test_object)

        assert result == 'ARM'
        assert self.analysis_plugin.make_summary(result, None, None) == ['ARM']

    def test_cpu_architecture_not_found(self):

        test_object = FileObject()
        test_object.processed_analysis['cpu_architecture'] = {'summary': []}
        result = self.analysis_plugin.cpu_architecture_analysis(test_object)

        assert result is None
        assert self.analysis_plugin.make_summary(result, None, None) == []

    def test_kernel_config_found(self):

        test_object = FileObject()
        test_object.processed_analysis['kernel_config'] = {
            'kernel_config': 'This is a test\n#This is not important\nThis is important'
        }
        result = self.analysis_plugin.filter_kernel_config(test_object)

        assert result[0] == 'This is a test'
        assert result[1] == 'This is important'
        assert self.analysis_plugin.make_summary(None, None, result) == ['kernel_config available']
