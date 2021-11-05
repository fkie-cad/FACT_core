from objects.file import FileObject
from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest

from ..code.hello_world import AnalysisPlugin


class test_analysis_plugin_Hello_World(AnalysisPluginTest):

    PLUGIN_NAME = 'Hello_World'

    def setUp(self):
        super().setUp()
        config = self.init_basic_config()
        # additional config can go here
        # additional setup can go here
        self.analysis_plugin = AnalysisPlugin(self, config=config)

    def tearDown(self):
        super().tearDown()
        # additional tearDown can go here

    def test_plugin(self):
        test_object = FileObject()
        self.analysis_plugin.process_object(test_object)

        self.assertEqual(test_object.processed_analysis[self.PLUGIN_NAME]['analysis_result_a'], 'hello world')
