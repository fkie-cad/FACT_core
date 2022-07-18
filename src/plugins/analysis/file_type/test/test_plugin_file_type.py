from objects.file import FileObject
from test.common_helper import get_test_data_dir  # pylint: disable=wrong-import-order
from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest  # pylint: disable=wrong-import-order

from ..code.file_type import AnalysisPlugin


class TestAnalysisPluginFileType(AnalysisPluginTest):

    PLUGIN_NAME = 'file_type'
    PLUGIN_CLASS = AnalysisPlugin

    def test_detect_type_of_file(self):
        test_file = FileObject(file_path=f'{get_test_data_dir()}/container/test.zip')
        test_file = self.analysis_plugin.process_object(test_file)
        analysis = test_file.processed_analysis[self.PLUGIN_NAME]
        assert analysis['result']['mime'] == 'application/zip', 'mime-type not detected correctly'
        assert analysis['result']['full'].startswith('Zip archive data, at least'), 'full type not correct'
        assert analysis['summary'] == ['application/zip']
