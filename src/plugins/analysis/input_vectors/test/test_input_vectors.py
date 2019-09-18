from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest
from objects.file import FileObject

from ..code.input_vectors import AnalysisPlugin


class test_analysis_plugin_input_vectors(AnalysisPluginTest):

    PLUGIN_NAME = 'input_vectors'

    def setUp(self):
        super().setUp()
        config = self.init_basic_config()
        self.analysis_plugin = AnalysisPlugin(self, config=config)

    def tearDown(self):
        super().tearDown()
