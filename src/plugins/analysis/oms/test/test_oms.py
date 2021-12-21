from pathlib import Path

from test.common_helper import create_test_file_object
from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest

from ..code.oms import AnalysisPlugin

TEST_FILE = Path(__file__).parent / 'data' / 'eicar.zip'


class TestAnalysisPluginFileType(AnalysisPluginTest):

    PLUGIN_NAME = AnalysisPlugin.NAME

    def setUp(self):
        super().setUp()
        config = self.init_basic_config()
        self.analysis_plugin = AnalysisPlugin(self, config=config)

    def test_process_object(self):
        assert TEST_FILE.is_file(), 'test file is missing, please re-run installation'
        fo = create_test_file_object(bin_path=TEST_FILE)

        self.analysis_plugin.process_object(fo)

        assert self.PLUGIN_NAME in fo.processed_analysis
        assert fo.processed_analysis[self.PLUGIN_NAME] != {}
        assert fo.processed_analysis[self.PLUGIN_NAME]['positives'] == 1
        assert fo.processed_analysis[self.PLUGIN_NAME]['scans']['ClamAV']['result'] == 'Win.Test.EICAR_HDB-1'
