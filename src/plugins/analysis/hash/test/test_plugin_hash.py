import os

from common_helper_files import get_dir_of_file

from test.common_helper import MockFileObject
from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest

from ..code.hash import AnalysisPlugin

TEST_DATA_DIR = os.path.join(get_dir_of_file(__file__), 'data')


class TestAnalysisPluginHash(AnalysisPluginTest):

    PLUGIN_NAME = 'file_hashes'

    def setUp(self):
        super().setUp()
        config = self.init_basic_config()
        config.set(self.PLUGIN_NAME, 'hashes', 'md5, sha1, foo')
        self.analysis_plugin = AnalysisPlugin(self, config=config)

    def tearDown(self):
        super().tearDown()

    def test_all_hashes(self):
        self.fo = MockFileObject()
        result = self.analysis_plugin.process_object(self.fo).processed_analysis[self.PLUGIN_NAME]

        assert 'md5' in result, 'md5 not in result'
        assert 'sha1' in result, 'sha1 not in result'
        assert 'foo' not in result, 'foo in result but not available'
        assert result['md5'] == '6f8db599de986fab7a21625b7916589c', 'hash not correct'
        assert 'ssdeep' in result, 'ssdeep not in result'
        assert 'imphash' in result, 'imphash not in result'

    def test_imphash(self):
        file_path = os.path.join(TEST_DATA_DIR, 'ls')
        result = self.analysis_plugin.process_object(MockFileObject(file_path=file_path)).processed_analysis[self.PLUGIN_NAME]

        assert isinstance(result['imphash'], str), 'imphash should be a string'
        assert len(result['imphash']) == 32, 'imphash does not look like an md5'
