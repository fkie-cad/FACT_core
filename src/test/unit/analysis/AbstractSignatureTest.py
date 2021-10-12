# pylint: disable=no-member,wrong-import-order

import os

from objects.file import FileObject
from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest


class AbstractSignatureTest(AnalysisPluginTest):

    def _rule_match(self, filename, expected_rule_name, expected_number_of_rules=1):
        path = os.path.join(self.TEST_DATA_DIR, filename)
        test_file = FileObject(file_path=path)
        self.analysis_plugin.process_object(test_file)
        number_of_rules = len(test_file.processed_analysis[self.PLUGIN_NAME]) - 1
        assert number_of_rules == expected_number_of_rules, f'Number of results is {number_of_rules} but should be {expected_number_of_rules}'
        if expected_rule_name is not None:
            assert expected_rule_name in test_file.processed_analysis[self.PLUGIN_NAME], f'Expected rule {expected_rule_name} missing'
