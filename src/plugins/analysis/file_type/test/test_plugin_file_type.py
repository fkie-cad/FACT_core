from objects.file import FileObject
from test.common_helper import get_test_data_dir
from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest

from ..code.file_type import AnalysisPlugin


class TestAnalysisPluginFileType(AnalysisPluginTest):

    PLUGIN_NAME = 'file_type'

    def setUp(self):
        super().setUp()
        config = self.init_basic_config()
        self.analysis_plugin = AnalysisPlugin(self, config=config)

    def test_detect_type_of_file(self):
        test_file = FileObject(file_path='{}/container/test.zip'.format(get_test_data_dir()))
        test_file = self.analysis_plugin.process_object(test_file)
        assert test_file.processed_analysis[self.PLUGIN_NAME]['mime'] == 'application/zip', 'mime-type not detected correctly'
        assert test_file.processed_analysis[self.PLUGIN_NAME]['full'].startswith('Zip archive data, at least'), 'full type not correct'
        assert test_file.processed_analysis[self.PLUGIN_NAME]['summary'] == ['application/zip']
