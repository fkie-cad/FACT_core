from test.common_helper import create_test_file_object
from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest

from ..code.string_eval import AnalysisPlugin


class TestAnalysisPlugInStringEvaluator(AnalysisPluginTest):

    PLUGIN_NAME = 'string_evaluator'
    PLUGIN_CLASS = AnalysisPlugin

    def test_find_strings(self):
        fo = create_test_file_object()
        fo.processed_analysis['printable_strings'] = dict(
            strings=['reasonable', 'still_reasonable', 'n123ot\'(§rea\'§&son##+able']
        )

        fo = self.analysis_plugin.process_object(fo)
        results = fo.processed_analysis[self.PLUGIN_NAME]

        self.assertTrue(isinstance(results, dict), 'Result of wrong type')
        self.assertTrue(results['string_eval'] == ['still_reasonable', 'reasonable', 'n123ot\'(§rea\'§&son##+able'])
