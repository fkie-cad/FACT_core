import pytest

from common_helper_files import get_dir_of_file
import os
import json
from objects.file import FileObject
from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest

from ..code.known_vulnerabilities import AnalysisPlugin, SoftwareRule, BadRuleError


TEST_DATA_DIR = os.path.join(get_dir_of_file(__file__), 'data')


class TestAnalysisPluginsKnownVulnerabilities(AnalysisPluginTest):

    PLUGIN_NAME = 'known_vulnerabilities'

    def setUp(self):
        super().setUp()
        config = self.init_basic_config()
        self.analysis_plugin = AnalysisPlugin(self, config=config)

    def test_process_object_yara(self):
        test_file = FileObject(file_path=os.path.join(TEST_DATA_DIR, 'testfile'))
        test_file.processed_analysis['software_components'] = {}

        results = self.analysis_plugin.process_object(test_file).processed_analysis[self.PLUGIN_NAME]

        self.assertEqual(len(results), 2, 'incorrect number of software components found (summary + one result)')
        self.assertTrue('DLink_Bug' in results, 'test match not found')
        self.assertEqual(results['DLink_Bug']['score'], 'high', 'incorrect or no score found in meta data')

    def test_process_object_software(self):
        test_file = FileObject(file_path=os.path.join(TEST_DATA_DIR, 'empty'))
        with open(os.path.join(TEST_DATA_DIR, 'sc.json'), 'r') as json_file:
            test_file.processed_analysis['software_components'] = json.load(json_file)

        results = self.analysis_plugin.process_object(test_file).processed_analysis[self.PLUGIN_NAME]

        self.assertEqual(len(results), 2, 'incorrect number of software components found (summary + one result)')
        self.assertTrue('OpenSSL' in results, 'test match not found')
        self.assertEqual(results['OpenSSL']['score'], 'high', 'incorrect or no score found in meta data')


@pytest.mark.parametrize('reliability', ['no_integer', None, '200'])
def test_bad_reliability(reliability):
    with pytest.raises(BadRuleError):
        SoftwareRule(description='', score='high', reliability=reliability)


@pytest.mark.parametrize('score', ['higher', None, 50])
def test_bad_score(score):
    with pytest.raises(BadRuleError):
        SoftwareRule(description='', score=score, reliability='50')


@pytest.mark.parametrize('description', [None, ])
def test_bad_description(description):
    with pytest.raises(BadRuleError):
        SoftwareRule(description=description, score='high', reliability='50')
