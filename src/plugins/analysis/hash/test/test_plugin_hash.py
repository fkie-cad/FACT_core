from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest

from ..code.hash import AnalysisPlugin
from objects.file import FileObject


class test_analysis_plugin_hash(AnalysisPluginTest):

    PLUGIN_NAME = 'file_hashes'

    def setUp(self):
        super().setUp()
        config = self.init_basic_config()
        config.set(self.PLUGIN_NAME, 'hashes', 'md5, sha1, foo')
        self.analysis_plugin = AnalysisPlugin(self, config=config)
        self.fo = FileObject(binary=b'test string')

    def tearDown(self):
        super().tearDown()
        # additional tearDown can go here

    def test_all_hashes(self):
        result = self.analysis_plugin.process_object(self.fo).processed_analysis[self.PLUGIN_NAME]
        self.assertIn('md5', result, 'md5 not in result')
        self.assertIn('sha1', result, 'sha1 not in result')
        self.assertNotIn('foo', result, 'foo in result but not available')
        self.assertEqual(result['md5'], '6f8db599de986fab7a21625b7916589c', 'hash not correct')
        self.assertIn('ssdeep', result, 'ssdeep not in result')
