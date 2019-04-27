from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest

from ..code.tlsh import AnalysisPlugin


class TestAnalysisPluginTLSH(AnalysisPluginTest):

    PLUGIN_NAME = 'tlsh'

    def setUp(self):
        super().setUp()
        config = self.init_basic_config()
        # additional config can go here
        # additional setup can go here
        self.analysis_plugin = AnalysisPlugin(self, config=config)

    def tearDown(self):
        super().tearDown()
        # additional tearDown can go here

    def test_tlsh(self):
        pass
