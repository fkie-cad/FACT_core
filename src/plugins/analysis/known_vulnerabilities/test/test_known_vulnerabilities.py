import json
from io import FileIO
from pathlib import Path

import pytest

from plugins.analysis.hash.code.hash import AnalysisPlugin as HashPlugin
from plugins.analysis.known_vulnerabilities.code.known_vulnerabilities import AnalysisPlugin
from plugins.analysis.software_components.code.software_components import AnalysisPlugin as SoftwarePlugin

TEST_DATA_DIR = Path(__file__).parent / 'data'


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
class TestAnalysisPluginsKnownVulnerabilities:
    _software_components_result = json.loads((TEST_DATA_DIR / 'sc.json').read_text())

    def test_process_object_yara(self, analysis_plugin):
        dependencies = {
            'file_hashes': HashPlugin.Schema(md5='1234', sha256='1234'),
            'software_components': SoftwarePlugin.Schema(software_components=[]),
        }
        results = analysis_plugin.analyze(FileIO(str(TEST_DATA_DIR / 'testfile')), {}, dependencies)
        summary = analysis_plugin.summarize(results)
        tags = analysis_plugin.get_tags(results, summary)
        vulns_by_name = {v.name: v for v in results.vulnerabilities}
        tags_by_name = {t.name: t for t in tags}

        assert len(results.vulnerabilities) == 2, 'incorrect number of vulnerabilities'
        assert 'DLink_Bug' in vulns_by_name, 'test match not found'
        assert vulns_by_name['DLink_Bug'].score == 'high', 'incorrect or no score found in meta data'

        assert 'DLink_Bug' in summary
        assert 'DLink_Bug' in tags_by_name
        assert tags_by_name['DLink_Bug'].propagate

    def test_process_object_software(self, analysis_plugin):
        dependencies = {
            'file_hashes': HashPlugin.Schema(md5='1234', sha256='1234'),
            'software_components': SoftwarePlugin.Schema(**self._software_components_result['result']),
        }
        results = analysis_plugin.analyze(FileIO(str(TEST_DATA_DIR / 'empty')), {}, dependencies)
        summary = analysis_plugin.summarize(results)
        vulns_by_name = {v.name: v for v in results.vulnerabilities}

        assert len(results.vulnerabilities) == 1, 'incorrect number of vulnerabilities found'
        assert 'Heartbleed' in vulns_by_name, 'test match not found'
        assert 'Heartbleed' in summary
        assert vulns_by_name['Heartbleed'].score == 'high', 'incorrect or no score found in meta data'

    def test_process_object_software_wrong_version(self, analysis_plugin):
        software_components_result = {**self._software_components_result['result']}
        software_components_result['software_components'][0]['versions'] = ['0.9.8', '1.0.0']
        dependencies = {
            'file_hashes': HashPlugin.Schema(md5='1234', sha256='1234'),
            'software_components': SoftwarePlugin.Schema(**software_components_result),
        }
        results = analysis_plugin.analyze(FileIO(str(TEST_DATA_DIR / 'empty')), {}, dependencies)
        summary = analysis_plugin.summarize(results)

        assert len(results.vulnerabilities) == 0
        assert len(summary) == 0

    def test_process_object_hash(self, analysis_plugin):
        dependencies = {
            'file_hashes': HashPlugin.Schema(
                md5='1234',
                sha256='7579d10e812905e134cf91ad8eef7b08f87f6f8c8e004ebefa441781fea0ec4a',
            ),
            'software_components': SoftwarePlugin.Schema(software_components=[]),
        }
        results = analysis_plugin.analyze(FileIO(str(TEST_DATA_DIR / 'empty')), {}, dependencies)
        summary = analysis_plugin.summarize(results)
        tags = analysis_plugin.get_tags(results, summary)
        vulns_by_name = {v.name: v for v in results.vulnerabilities}
        tags_by_name = {t.name: t for t in tags}

        assert len(results.vulnerabilities) == 1
        assert 'Netgear_CGI' in vulns_by_name
        assert vulns_by_name['Netgear_CGI'].score == 'medium'

        assert 'Netgear_CGI' in tags_by_name
        assert not tags_by_name['Netgear_CGI'].propagate

    def test_netusb_vulnerable(self, analysis_plugin):
        test_path = TEST_DATA_DIR / 'netusb_vulnerable.elf'
        result = analysis_plugin._check_netusb_vulnerability(str(test_path))
        vulns_by_name = {v.name: v for v in result}
        assert len(result) == 1
        assert 'CVE-2021-45608' in vulns_by_name
        assert vulns_by_name['CVE-2021-45608'].additional_data['is_vulnerable'] is True

    def test_netusb_not_vulnerable(self, analysis_plugin):
        test_path = TEST_DATA_DIR / 'netusb_not_vulnerable.elf'
        result = analysis_plugin._check_netusb_vulnerability(str(test_path))
        vulns_by_name = {v.name: v for v in result}
        assert len(result) == 1
        assert 'CVE-2021-45608' in vulns_by_name
        assert vulns_by_name['CVE-2021-45608'].additional_data['is_vulnerable'] is False

    def test_netusb_error(self, analysis_plugin):
        test_path = TEST_DATA_DIR / 'testfile'
        result = analysis_plugin._check_netusb_vulnerability(str(test_path))
        assert len(result) == 0

    def test_xz_backdoor_1st(self, analysis_plugin):
        dependencies = {
            'file_hashes': HashPlugin.Schema(md5='1234', sha256='1234'),
            'software_components': SoftwarePlugin.Schema(software_components=[]),
        }
        results = analysis_plugin.analyze(FileIO(str(TEST_DATA_DIR / 'xz_backdoor_test_file')), {}, dependencies)
        summary = analysis_plugin.summarize(results)
        vulns_by_name = {v.name: v for v in results.vulnerabilities}
        assert 'xz_backdoor' in vulns_by_name
        assert 'xz_backdoor' in summary

    def test_xz_backdoor_2nd(self, analysis_plugin):
        dependencies = {
            'file_hashes': HashPlugin.Schema(md5='1234', sha256='1234'),
            'software_components': SoftwarePlugin.Schema(
                software_components=[{'name': 'liblzma', 'versions': ['5.6.1'], 'rule': '', 'matching_strings': []}]
            ),
        }
        results = analysis_plugin.analyze(FileIO(str(TEST_DATA_DIR / 'empty')), {}, dependencies)
        summary = analysis_plugin.summarize(results)
        vulns_by_name = {v.name: v for v in results.vulnerabilities}

        assert 'XZ Backdoor' in vulns_by_name
        assert 'XZ Backdoor' in summary
