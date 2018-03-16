import pytest

from common_helper_files import get_dir_of_file
import os
import json
from objects.file import FileObject
from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest

from ..code.known_vulnerabilities import AnalysisPlugin
from ..internal.software_rules import SoftwareRule, BadRuleError


TEST_DATA_DIR = os.path.join(get_dir_of_file(__file__), 'data')


class TestAnalysisPluginsKnownVulnerabilities(AnalysisPluginTest):

    PLUGIN_NAME = 'known_vulnerabilities'

    def setUp(self):
        super().setUp()
        config = self.init_basic_config()
        self.analysis_plugin = AnalysisPlugin(self, config=config)
        with open(os.path.join(TEST_DATA_DIR, 'sc.json'), 'r') as json_file:
            self._software_components_result = json.load(json_file)

    def test_process_object_yara(self):
        test_file = FileObject(file_path=os.path.join(TEST_DATA_DIR, 'testfile'))
        test_file.processed_analysis['file_hashes'] = {'sha256': '1234'}
        test_file.processed_analysis['software_components'] = {}

        results = self.analysis_plugin.process_object(test_file).processed_analysis[self.PLUGIN_NAME]

        self.assertEqual(len(results), 2, 'incorrect number of software components found (summary + one result)')
        self.assertTrue('DLink_Bug' in results, 'test match not found')
        self.assertEqual(results['DLink_Bug']['score'], 'high', 'incorrect or no score found in meta data')

    def test_process_object_software(self):
        test_file = FileObject(file_path=os.path.join(TEST_DATA_DIR, 'empty'))
        test_file.processed_analysis['file_hashes'] = {'sha256': '1234'}
        test_file.processed_analysis['software_components'] = self._software_components_result

        results = self.analysis_plugin.process_object(test_file).processed_analysis[self.PLUGIN_NAME]

        self.assertEqual(len(results), 2, 'incorrect number of software components found (summary + one result)')
        self.assertTrue('OpenSSL' in results, 'test match not found')
        self.assertEqual(results['OpenSSL']['score'], 'high', 'incorrect or no score found in meta data')

    def test_process_object_software_wrong_version(self):
        test_file = FileObject(file_path=os.path.join(TEST_DATA_DIR, 'empty'))
        test_file.processed_analysis['file_hashes'] = {'sha256': '1234'}
        self._software_components_result['OpenSSL']['meta']['version'] = ['0.9.8', '1.0.0', '']
        test_file.processed_analysis['software_components'] = self._software_components_result

        results = self.analysis_plugin.process_object(test_file).processed_analysis[self.PLUGIN_NAME]

        self.assertCountEqual(['summary'], list(results.keys()), 'no match should be found')

    def test_process_object_hash(self):
        test_file = FileObject(file_path=os.path.join(TEST_DATA_DIR, 'empty'))
        test_file.processed_analysis['file_hashes'] = {'sha256': '7579d10e812905e134cf91ad8eef7b08f87f6f8c8e004ebefa441781fea0ec4a'}
        test_file.processed_analysis['software_components'] = {}

        results = self.analysis_plugin.process_object(test_file).processed_analysis[self.PLUGIN_NAME]

        self.assertEqual(len(results), 2, 'incorrect number of software components found (summary + one result)')
        self.assertTrue('Netgear_CGI' in results, 'test match not found')
        self.assertEqual(results['Netgear_CGI']['score'], 'medium', 'incorrect or no score found in meta data')


@pytest.mark.parametrize('reliability', ['no_integer', None, '200'])
def test_bad_reliability(reliability):
    with pytest.raises(BadRuleError):
        SoftwareRule(description='', score='high', reliability=reliability, software='name')


@pytest.mark.parametrize('score', ['higher', None, 50])
def test_bad_score(score):
    with pytest.raises(BadRuleError):
        SoftwareRule(description='', score=score, reliability='50', software='name')


@pytest.mark.parametrize('description', [None, 12, dict(prefix='any')])
def test_bad_description(description):
    with pytest.raises(BadRuleError):
        SoftwareRule(description=description, score='high', reliability='50', software='name')
