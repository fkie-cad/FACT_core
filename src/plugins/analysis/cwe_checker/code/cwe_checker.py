"""
This plugin implements a wrapper around the cwe_checker, which checks ELF executables for
several CWEs (Common Weakness Enumeration). Please refer to cwe_checkers implementation for further information.
Please note that these checks are heuristics and the checks are static.
This means that there are definitely false positives and false negatives. The objective of this
plugin is to find potentially interesting binaries that deserve a deep manual analysis or intensive fuzzing.

Currently, the cwe_checker supports the following architectures:
- Intel x86 (32 and 64 bits)
- ARM
- PowerPC
- Mips
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from typing import TYPE_CHECKING, List

from docker.types import Mount
from pydantic import BaseModel
from requests import RequestException
from semver import Version

import config
from analysis.plugin import AnalysisFailedError, AnalysisPluginV0
from helperFunctions.docker import run_docker_container

if TYPE_CHECKING:
    from io import FileIO

DOCKER_IMAGE = 'fkiecad/cwe_checker:stable'
SUPPORTED_ARCHS = ('arm', 'x86', 'x64', 'mips', 'ppc')


class CweResult(BaseModel):
    cwe_id: str
    warnings: List[str]
    plugin_version: str


class AnalysisPlugin(AnalysisPluginV0):
    class Schema(BaseModel):
        cwe_results: List

    def __init__(self):
        super().__init__(
            metadata=(
                self.MetaData(
                    name='cwe_checker',
                    description=(
                        'This plugin checks ELF binaries for several CWEs (Common Weakness Enumeration) like'
                        'CWE-243 (Creation of chroot Jail Without Changing Working Directory) and'
                        'CWE-676 (Use of Potentially Dangerous Function).'
                        'Due to the nature of static analysis, this plugin may run for a long time.'
                    ),
                    dependencies=['cpu_architecture', 'file_type'],
                    mime_whitelist=[
                        'application/x-executable',
                        'application/x-pie-executable',
                        'application/x-sharedlib',
                    ],
                    version=Version(1, 0, 1),
                    Schema=self.Schema,
                )
            )
        )
        self._log_version_string()
        self.memory_limit = getattr(config.backend.plugin.get(self.metadata.name, None), 'memory_limit', '4G')
        self.swap_limit = getattr(config.backend.plugin.get(self.metadata.name, None), 'memswap_limit', '4G')

    def _log_version_string(self):
        output = self._run_cwe_checker_to_get_version_string()
        if output is None:
            logging.error('Could not get version string from cwe_checker.')
        else:
            logging.debug(f'Version is {output}')
        return output

    @staticmethod
    def _run_cwe_checker_to_get_version_string():
        result = run_docker_container(
            DOCKER_IMAGE,
            combine_stderr_stdout=True,
            timeout=60,
            command='--version',
        )
        return result.stdout

    def _run_cwe_checker_in_docker(self, file_path: str) -> bytes:
        result = run_docker_container(
            DOCKER_IMAGE,
            combine_stderr_stdout=True,
            timeout=self.metadata.timeout - 30,
            command='/input --json --quiet',
            mounts=[
                Mount('/input', file_path, type='bind'),
            ],
            mem_limit=self.memory_limit,
            memswap_limit=self.swap_limit,
        )
        return result.stdout

    @staticmethod
    def _parse_cwe_checker_output(output):
        tmp = defaultdict(list)
        j_doc = json.loads(output)
        for warning in j_doc:
            tmp[warning['name']] = tmp[warning['name']] + [
                warning,
            ]

        res = {}
        for key, values in tmp.items():
            tmp_list = []
            plugin_version = None
            for hit in values:
                tmp_list.append(hit['description'])
                if not plugin_version:
                    plugin_version = hit['version']
            res[key] = {'plugin_version': plugin_version, 'warnings': tmp_list}

        return res

    @staticmethod
    def _is_supported_arch(file_type_analysis: BaseModel) -> bool:
        arch_type = file_type_analysis.full.lower()
        return any(supported_arch in arch_type for supported_arch in SUPPORTED_ARCHS)

    def _do_full_analysis(self, file_path: str) -> dict:
        try:
            output = self._run_cwe_checker_in_docker(file_path)
        except RequestException as e:
            raise AnalysisFailedError('No response from cwe_checker Docker container (possible timeout)') from e
        if output is None:
            raise AnalysisFailedError('cwe_checker output is missing (timeout or error during execution)')
        try:
            return self._parse_cwe_checker_output(output)
        except json.JSONDecodeError as error:
            raise AnalysisFailedError('cwe_checker execution failed: Could not parse output') from error

    def analyze(self, file_handle: FileIO, virtual_file_path: dict, analyses: dict[str, BaseModel]) -> Schema:
        """
        This function handles only ELF executables. Otherwise, it returns an empty dictionary.
        It calls the cwe_checker docker container.
        """
        del virtual_file_path
        if not self._is_supported_arch(analyses['file_type']):
            full_type = analyses['file_type'].full
            arch = full_type.split(',')[1].strip() if full_type.startswith('ELF') else 'Unknown'
            raise AnalysisFailedError(f'Unsupported architecture: {arch}')
        result = self._do_full_analysis(file_handle.name)

        return self.Schema(
            cwe_results=[
                CweResult(cwe_id=cwe_id, warnings=data['warnings'], plugin_version=data['plugin_version'])
                for cwe_id, data in result.items()
            ]
        )

    def summarize(self, result: Schema) -> list[str]:
        return [cwe.cwe_id for cwe in result.cwe_results] if result else []
