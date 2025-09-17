from __future__ import annotations

import json
from contextlib import suppress
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import TYPE_CHECKING, List, Optional

from docker.errors import DockerException
from docker.types import Mount
from pydantic import BaseModel
from semver import Version

import config
from analysis.plugin import AnalysisPluginV0, Tag, addons
from helperFunctions.docker import run_docker_container
from helperFunctions.tag import TagColor

from ..internal.rulebook import evaluate, vulnerabilities

if TYPE_CHECKING:
    from io import FileIO

VULNERABILITIES = vulnerabilities()


class Vulnerability(BaseModel):
    name: str
    link: Optional[str] = None
    score: Optional[str] = None
    description: Optional[str] = None
    reliability: Optional[str] = None
    additional_data: Optional[dict] = None


class AnalysisPlugin(AnalysisPluginV0):
    class Schema(BaseModel):
        vulnerabilities: List[Vulnerability]

    def __init__(self):
        metadata = self.MetaData(
            name='known_vulnerabilities',
            description='Rule based detection of known vulnerabilities like Heartbleed',
            dependencies=['file_hashes', 'software_components'],
            version=Version(1, 0, 0),
            Schema=self.Schema,
        )
        super().__init__(metadata=metadata)
        self._yara = addons.Yara(plugin=self)

    def analyze(self, file_handle: FileIO, virtual_file_path: str, analyses: dict) -> Schema:
        del virtual_file_path
        yara_vulnerabilities = self._get_yara_vulnerabilities(file_handle)
        matched_vulnerabilities = self.get_matched_vulnerabilities(yara_vulnerabilities, analyses, file_handle.name)
        return AnalysisPlugin.Schema(
            vulnerabilities=yara_vulnerabilities + matched_vulnerabilities,
        )

    def _get_yara_vulnerabilities(self, file_handle: FileIO) -> list[Vulnerability]:
        return [
            Vulnerability(
                name=m.rule,
                link=m.meta.get('link'),
                score=m.meta.get('score'),
                description=m.meta.get('description'),
                reliability=m.meta.get('reliability'),
            )
            for m in self._yara.match(file_handle)
        ]

    def get_matched_vulnerabilities(
        self, yara_result: list[Vulnerability], analyses: dict, path: str
    ) -> list[Vulnerability]:
        software_by_name = {
            sw_match.name: sw_match.model_dump() for sw_match in analyses['software_components'].software_components
        }
        matched_vulnerabilities = self._check_vulnerabilities(analyses)

        # CVE-2021-45608 NetUSB
        if 'NetUSB' in software_by_name:
            matched_vulnerabilities.extend(self._check_netusb_vulnerability(path))

        # CVE-2024-3094 XZ Backdoor secondary detection
        if 'liblzma' in software_by_name and not any(vuln == 'xz_backdoor' for vuln, _ in yara_result):
            matched_vulnerabilities.extend(_check_xz_backdoor(software_by_name['liblzma']))
        return matched_vulnerabilities

    def summarize(self, result: Schema) -> list[str]:
        return list({v.name for v in result.vulnerabilities})

    def get_tags(self, result: Schema, summary: list[str]) -> list[Tag]:
        del summary
        tags = []
        for vuln in result.vulnerabilities:
            if vuln.score == 'none':
                continue
            if vuln.score == 'high':
                propagate = True
                tag_color = TagColor.RED
            else:
                propagate = False
                tag_color = TagColor.ORANGE
            tags.append(
                Tag(
                    name=vuln.name,
                    value=vuln.name.replace('_', ' '),
                    color=tag_color,
                    propagate=propagate,
                )
            )
        return tags

    @staticmethod
    def _check_vulnerabilities(dependency_analyses: dict) -> list[Vulnerability]:
        result = []
        for vulnerability in VULNERABILITIES:
            if evaluate(dependency_analyses, vulnerability.rule):
                result.append(
                    Vulnerability(
                        name=vulnerability.short_name,
                        description=vulnerability.description,
                        link=vulnerability.link,
                        score=vulnerability.score,
                        reliability=vulnerability.reliability,
                    )
                )
        return result

    def _check_netusb_vulnerability(self, file_path: str) -> list[Vulnerability]:
        with TemporaryDirectory(prefix='known_vulns_', dir=config.backend.docker_mount_base_dir) as tmp_dir:
            tmp_dir_path = Path(tmp_dir)
            with suppress(DockerException, TimeoutError):
                run_docker_container(
                    'fact/known-vulnerabilities',
                    logging_label=self.metadata.name,
                    timeout=60,
                    mounts=[
                        Mount('/io', tmp_dir, type='bind'),
                        Mount('/io/ghidra_input', file_path, type='bind', read_only=True),
                    ],
                )

            try:
                ghidra_results = json.loads((tmp_dir_path / 'result.json').read_text())
                return [
                    Vulnerability(
                        name='CVE-2021-45608',
                        description='CVE-2021-45608: vulnerability in KCodes NetUSB kernel module',
                        score='high' if ghidra_results['is_vulnerable'] is True else 'none',
                        reliability='90',
                        link='https://nvd.nist.gov/vuln/detail/CVE-2021-45608',
                        additional_data=ghidra_results,
                    )
                ]
            except (json.JSONDecodeError, FileNotFoundError):
                return []


def _check_xz_backdoor(software_results: dict) -> list[Vulnerability]:
    if any(v in software_results['versions'] for v in ['5.6.0', '5.6.1']):
        return [
            Vulnerability(
                description='CVE-2024-3094: a malicious backdoor was planted into the xz compression library',
                score='high',
                # the vulnerability is only contained in certain versions built for debian; a more reliable
                # yara rule is in the signature files
                reliability='20',
                link='https://nvd.nist.gov/vuln/detail/CVE-2024-3094',
                name='XZ Backdoor',
            )
        ]
    return []
