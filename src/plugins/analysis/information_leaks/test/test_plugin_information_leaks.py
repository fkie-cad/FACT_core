from test.common_helper import MockFileObject
from pathlib import Path

from ..code.information_leaks import AnalysisPlugin

from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest

TEST_DATA_DIR = Path(__file__).parent/'data'


class TestAnalysisPluginInformationLeaks(AnalysisPluginTest):

    PLUGIN_NAME = 'information_leaks'

    def setUp(self):
        super().setUp()
        config = self.init_basic_config()
        self.analysis_plugin = AnalysisPlugin(self, config=config)

    def test_find_path(self):
        fo = MockFileObject()
        fo.binary = (TEST_DATA_DIR / 'path_test_file').read_bytes()
        fo.processed_analysis[self.PLUGIN_NAME] = {}
        fo.virtual_file_path = {}
        self.analysis_plugin.process_object(fo)

        assert 'proc_paths' in fo.processed_analysis[self.PLUGIN_NAME]
        assert 'user_paths' in fo.processed_analysis[self.PLUGIN_NAME]

        expected_user_paths = [
            '/home/user/test/urandom',
            '/home/user/test/urandom_sehr_sehr_sehr-lang.txt',
            '/home/user/urandom'
        ]
        assert fo.processed_analysis[self.PLUGIN_NAME]['user_paths'] == expected_user_paths

    def test_find_git_repo(self):
        fo = MockFileObject()
        fo.binary = b'test_data'
        fo.processed_analysis[self.PLUGIN_NAME] = {}
        fo.virtual_file_path = {'firmware_uid': ['some_uid|/test/.git/config']}
        self.analysis_plugin.process_object(fo)

        assert fo.processed_analysis[self.PLUGIN_NAME]['git_repo'] == 'test_data'
