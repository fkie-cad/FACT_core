import json
import os
import sys

from analysis.YaraPluginBase import YaraBasePlugin

THIS_FILE = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(THIS_FILE, '..', 'internal'))
from software_rules import rules


class AnalysisPlugin(YaraBasePlugin):
    NAME = 'known_vulnerabilities'
    DESCRIPTION = 'Rule based detection of known vulnerabilities like Heartbleed'
    DEPENDENCIES = ['software_components', 'file_hashes']
    VERSION = '0.1'
    FILE = __file__

    def __init__(self, plugin_administrator, config=None, recursive=True):
        self._software_rules = rules()
        self._hash_rules = self._initialize_hash_rules()

        super().__init__(plugin_administrator, config=config, recursive=recursive, plugin_path=__file__)

    def process_object(self, file_object):
        file_object = super().process_object(file_object)

        yara_results = file_object.processed_analysis.pop(self.NAME)
        binary_vulnerabilities, _ = self._post_process_yara_results(yara_results)

        software_vulnerabilies = self._check_software_components(file_object.processed_analysis['software_components'])

        hash_vulnerabilities = self._check_hash_vulnerabilities(file_object.processed_analysis['file_hashes']['sha256'])

        file_object.processed_analysis[self.NAME] = dict()
        for name, vulnerability in software_vulnerabilies + binary_vulnerabilities + hash_vulnerabilities:
            file_object.processed_analysis[self.NAME][name] = vulnerability

        file_object.processed_analysis[self.NAME]['summary'] = [item[0] for item in binary_vulnerabilities + software_vulnerabilies + hash_vulnerabilities]

        return file_object

    @staticmethod
    def _post_process_yara_results(yara_results):
        summary = yara_results.pop('summary')
        new_results = list()
        for result in yara_results:
            meta = yara_results[result]['meta']
            new_results.append((result, meta))
        return new_results, summary

    def _check_software_components(self, software_components_result):
        found_vulnerabilities = list()
        for software_component in software_components_result.keys():
            for rule in self._software_rules:
                if rule.software.lower() == software_component.lower():
                    component = software_components_result[software_component]
                    component_version = None

                    for version in component['meta']['version']:
                        if version:
                            component_version = version
                    if rule.is_vulnerable(component_version):
                        found_vulnerabilities.append((software_component, rule.get_dict()))
        return found_vulnerabilities

    @staticmethod
    def _initialize_hash_rules():
        rule_file = os.path.join(THIS_FILE, '..', 'internal/hash_rules.json')
        with open(rule_file, 'r') as fd:
            rules = json.load(fd)
        return rules

    def _check_hash_vulnerabilities(self, sha256_hash):
        vulnerabilities = list()

        for rule in self._hash_rules :
            if sha256_hash == rule['sha256']:
                rule.pop('sha256')
                name = rule.pop('name')
                vulnerabilities.append((name, rule))
        return vulnerabilities
