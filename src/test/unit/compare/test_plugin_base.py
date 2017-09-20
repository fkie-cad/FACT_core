from test.unit.compare.compare_plugin_test_class import ComparePluginTest

from compare.PluginBase import ComparePluginBase as ComparePlugin


class test_ComparePluginBase(ComparePluginTest):

    # This name must be changed according to the name of plug-in to test
    PLUGIN_NAME = "base"

    def setup_plugin(self):
        """
        This function must be overwritten by the test instance.
        In most cases it is sufficient to copy this function.
        """
        return ComparePlugin(self, config=self.config)

    def test_dependency_check(self):
        self.c_plugin.DEPENDENCYS = ['test_ana']
        self.fw_one.processed_analysis['test_ana'] = {}
        self.assertEqual(self.c_plugin.check_dependencys([self.fw_one, self.fw_two]), ['test_ana'], "missing dependency not found")
        self.fw_two.processed_analysis['test_ana'] = {}
        self.assertEqual(self.c_plugin.check_dependencys([self.fw_one, self.fw_two]), [], "missing dependency found but all satisfied")

    def test_compare_missing_dep(self):
        self.c_plugin.DEPENDENCYS = ['test_ana']
        self.fw_one.processed_analysis['test_ana'] = {}
        self.assertEqual(self.c_plugin.compare([self.fw_one, self.fw_two]), {'Compare Skipped': {'all': "Required analysis not present: ['test_ana']"}}, "missing dep result not correct")

    def test_compare(self):
        self.assertEqual(self.c_plugin.compare([self.fw_one, self.fw_two]), {'dummy': {'all': 'dummy-content', 'collapse': False}}, "result not correct")
