import json
from contextlib import suppress
from pathlib import Path
from tempfile import TemporaryDirectory

from docker.errors import DockerException
from docker.types import Mount

import config
from analysis.YaraPluginBase import YaraBasePlugin
from helperFunctions.docker import run_docker_container
from helperFunctions.tag import TagColor

from ..internal.rulebook import evaluate, vulnerabilities

VULNERABILITIES = vulnerabilities()


class AnalysisPlugin(YaraBasePlugin):
    NAME = 'known_vulnerabilities'
    DESCRIPTION = 'Rule based detection of known vulnerabilities like Heartbleed'
    DEPENDENCIES = ['file_hashes', 'software_components']  # noqa: RUF012
    VERSION = '0.2.1'
    FILE = __file__

    def process_object(self, file_object):
        file_object = super().process_object(file_object)

        yara_results = file_object.processed_analysis.pop(self.NAME)
        file_object.processed_analysis[self.NAME] = {}

        binary_vulnerabilities = self._post_process_yara_results(yara_results)
        matched_vulnerabilities = self._check_vulnerabilities(file_object.processed_analysis)

        # CVE-2021-45608 NetUSB
        if 'NetUSB' in file_object.processed_analysis.get('software_components', {}).get('result', {}):
            matched_vulnerabilities.extend(self._check_netusb_vulnerability(file_object.binary))

        for name, vulnerability in binary_vulnerabilities + matched_vulnerabilities:
            file_object.processed_analysis[self.NAME][name] = vulnerability

        file_object.processed_analysis[self.NAME]['summary'] = [
            name for name, _ in binary_vulnerabilities + matched_vulnerabilities
        ]

        self.add_tags(file_object, binary_vulnerabilities + matched_vulnerabilities)

        return file_object

    def add_tags(self, file_object, vulnerability_list):
        for name, details in vulnerability_list:
            if details['score'] == 'none':
                continue
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
                propagate=propagate,
            )

    @staticmethod
    def _post_process_yara_results(yara_results):
        yara_results.pop('summary')
        new_results = []
        for result in yara_results:
            meta = yara_results[result]['meta']
            new_results.append((result, meta))
        return new_results

    @staticmethod
    def _check_vulnerabilities(processed_analysis):
        matched_vulnerabilities = []
        for vulnerability in VULNERABILITIES:
            if evaluate(processed_analysis, vulnerability.rule):
                vulnerability_data = vulnerability.get_dict()
                name = vulnerability_data.pop('short_name')
                matched_vulnerabilities.append((name, vulnerability_data))

        return matched_vulnerabilities

    def _check_netusb_vulnerability(self, input_file_data: bytes):
        with TemporaryDirectory(prefix='known_vulns_', dir=config.backend.docker_mount_base_dir) as tmp_dir:
            tmp_dir_path = Path(tmp_dir)
            ghidra_input_file = tmp_dir_path / 'ghidra_input'
            ghidra_input_file.write_bytes(input_file_data)
            with suppress(DockerException, TimeoutError):
                run_docker_container(
                    'fact/known-vulnerabilities',
                    logging_label=self.NAME,
                    timeout=60,
                    mounts=[
                        Mount('/io', tmp_dir, type='bind'),
                    ],
                )

            try:
                ghidra_results = json.loads((tmp_dir_path / 'result.json').read_text())
                return [
                    (
                        'CVE-2021-45608',
                        {
                            'description': 'CVE-2021-45608: vulnerability in KCodes NetUSB kernel module',
                            'score': 'high' if ghidra_results['is_vulnerable'] is True else 'none',
                            'reliability': 90,
                            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2021-45608',
                            'short_name': 'CVE-2021-45608',
                            'additional_data': ghidra_results,
                        },
                    )
                ]
            except (json.JSONDecodeError, FileNotFoundError):
                return []
