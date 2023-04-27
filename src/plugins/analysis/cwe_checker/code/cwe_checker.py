'''
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
'''
import json
import logging
from collections import defaultdict

from docker.types import Mount

from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.docker import run_docker_container

DOCKER_IMAGE = 'fkiecad/cwe_checker:stable'


class AnalysisPlugin(AnalysisBasePlugin):
    '''
    This class implements the FACT Python wrapper for the BAP plugin cwe_checker.
    '''

    NAME = 'cwe_checker'
    DESCRIPTION = (
        'This plugin checks ELF binaries for several CWEs (Common Weakness Enumeration) like'
        'CWE-243 (Creation of chroot Jail Without Changing Working Directory) and'
        'CWE-676 (Use of Potentially Dangerous Function).'
        'Due to the nature of static analysis, this plugin may run for a long time.'
    )
    DEPENDENCIES = ['cpu_architecture', 'file_type']
    VERSION = '0.5.2'
    TIMEOUT = 600  # 10 minutes
    MIME_WHITELIST = [
        'application/x-executable',
        'application/x-object',
        'application/x-pie-executable',
        'application/x-sharedlib',
    ]
    FILE = __file__

    SUPPORTED_ARCHS = ['arm', 'x86', 'x64', 'mips', 'ppc']

    def additional_setup(self):
        self._log_version_string()

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

    def _run_cwe_checker_in_docker(self, file_object):
        result = run_docker_container(
            DOCKER_IMAGE,
            combine_stderr_stdout=True,
            timeout=self.TIMEOUT - 30,
            command='/input --json --quiet',
            mounts=[
                Mount('/input', file_object.file_path, type='bind'),
            ],
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

    def _is_supported_arch(self, file_object):
        arch_type = file_object.processed_analysis['file_type']['result']['full'].lower()
        return any(supported_arch in arch_type for supported_arch in self.SUPPORTED_ARCHS)

    def _do_full_analysis(self, file_object):
        output = self._run_cwe_checker_in_docker(file_object)
        if output is not None:
            try:
                cwe_messages = self._parse_cwe_checker_output(output)
                file_object.processed_analysis[self.NAME] = {'full': cwe_messages, 'summary': list(cwe_messages.keys())}
            except json.JSONDecodeError:
                message = f'cwe_checker execution failed: {output}'
                logging.error(f'{message}\nUID: {file_object.uid}', exc_info=True)
                file_object.processed_analysis[self.NAME] = {'summary': [], 'failed': message}
        else:
            message = 'Timeout or error during cwe_checker execution.'
            logging.error(f'{message}\nUID: {file_object.uid}')
            file_object.processed_analysis[self.NAME] = {'summary': [], 'failed': message}
        return file_object

    def process_object(self, file_object):
        '''
        This function handles only ELF executables. Otherwise, it returns an empty dictionary.
        It calls the cwe_checker docker container.
        '''
        if not self._is_supported_arch(file_object):
            logging.debug(
                f'{file_object.file_path}\'s arch is not supported ('
                f'{file_object.processed_analysis["cpu_architecture"]["summary"]})'
            )
            file_object.processed_analysis[self.NAME] = {'summary': []}
        else:
            file_object = self._do_full_analysis(file_object)

        return file_object
