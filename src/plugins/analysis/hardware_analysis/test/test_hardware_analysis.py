from pathlib import Path

import pytest

from objects.file import FileObject
from test.common_helper import get_test_data_dir  # pylint: disable=wrong-import-order

from ..code.hardware_analysis import AnalysisPlugin

TEST_DATA = Path(get_test_data_dir())


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
class TestHardwareAnalysis:
    def test_cpu_architecture_found(self, analysis_plugin):
        test_object = FileObject()
        test_object.processed_analysis['cpu_architecture'] = {'summary': ['ARM']}
        result = analysis_plugin.cpu_architecture_analysis(test_object)

        assert result == 'ARM'
        assert analysis_plugin.make_summary(result, None, None) == ['ARM']

    def test_cpu_architecture_not_found(self, analysis_plugin):

        test_object = FileObject()
        test_object.processed_analysis['cpu_architecture'] = {'summary': []}
        result = analysis_plugin.cpu_architecture_analysis(test_object)

        assert result is None
        assert analysis_plugin.make_summary(result, None, None) == []

    def test_kernel_config_found(self, analysis_plugin):

        test_object = FileObject()

        test_object.processed_analysis['kernel_config'] = {
            'result': {
                'kernel_config': 'This is a test\n#This is not important\nThis is important',
            }
        }
        result = analysis_plugin.filter_kernel_config(test_object)

        assert result[0] == 'This is a test'
        assert result[1] == 'This is important'
        assert analysis_plugin.make_summary(None, None, result) == ['kernel_config available']
