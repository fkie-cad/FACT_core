import sys
from pathlib import Path

from analysis.YaraPluginBase import YaraBasePlugin
from helperFunctions.tag import TagColor

try:
    from ..internal.rulebook import evaluate, vulnerabilities
except ImportError:
    sys.path.append(str(Path(__file__).parent.parent / 'internal'))
    from rulebook import evaluate, vulnerabilities


class AnalysisPlugin(YaraBasePlugin):
    NAME = 'known_vulnerabilities'
    DESCRIPTION = 'Rule based detection of known vulnerabilities like Heartbleed'
    DEPENDENCIES = ['file_hashes', 'software_components']
    VERSION = '0.2'

    def __init__(self, plugin_administrator, config=None, recursive=True):
        self._rule_base_vulnerabilities = vulnerabilities()

        super().__init__(plugin_administrator, config=config, recursive=recursive, plugin_path=__file__)

    def process_object(self, file_object):
        file_object = super().process_object(file_object)

        yara_results = file_object.processed_analysis.pop(self.NAME)
        file_object.processed_analysis[self.NAME] = dict()

        binary_vulnerabilities, _ = self._post_process_yara_results(yara_results)
        matched_vulnerabilities = self._check_vulnerabilities(file_object.processed_analysis)

        for name, vulnerability in binary_vulnerabilities + matched_vulnerabilities:
            file_object.processed_analysis[self.NAME][name] = vulnerability

        file_object.processed_analysis[self.NAME]['summary'] = [name for name, _ in binary_vulnerabilities + matched_vulnerabilities]

        self.add_tags(file_object, binary_vulnerabilities + matched_vulnerabilities)

        return file_object

    def add_tags(self, file_object, vulnerability_list):
        for name, details in vulnerability_list:
            if details['score'] == 'high':
                propagate = True
                tag_color = TagColor.RED
            else:
                propagate = False
                tag_color = TagColor.ORANGE

            self.add_analysis_tag(
                file_object=file_object,
                tag_name=name,
                value=name.replace('_', ' '),
                color=tag_color,
                propagate=propagate
            )

    @staticmethod
    def _post_process_yara_results(yara_results):
        summary = yara_results.pop('summary')
        new_results = list()
        for result in yara_results:
            meta = yara_results[result]['meta']
            new_results.append((result, meta))
        return new_results, summary

    def _check_vulnerabilities(self, processed_analysis):
        matched_vulnerabilities = list()
        for vulnerability in self._rule_base_vulnerabilities:
            if evaluate(processed_analysis, vulnerability.rule):
                vulnerability_data = vulnerability.get_dict()
                name = vulnerability_data.pop('short_name')
                matched_vulnerabilities.append((name, vulnerability_data))

        return matched_vulnerabilities
