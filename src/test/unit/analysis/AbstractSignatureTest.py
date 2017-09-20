import os

from objects.file import FileObject
from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest


class AbstractSignatureTest(AnalysisPluginTest):

    def _rule_match(self, filename, expected_rule_name, expected_number_of_rules=1):
        path = os.path.join(self.TEST_DATA_DIR, filename)
        test_file = FileObject(file_path=path)
        self.analysis_plugin.process_object(test_file)
        self.assertEqual(len(test_file.processed_analysis[self.PLUGIN_NAME]), expected_number_of_rules + 1, 'Number of results is {} but should be {}'.format(len(test_file.processed_analysis[self.PLUGIN_NAME]) - 1, expected_number_of_rules))
        if expected_rule_name is not None:
            self.assertIn(expected_rule_name, test_file.processed_analysis[self.PLUGIN_NAME], 'Expected rule {} missing'.format(expected_rule_name))
