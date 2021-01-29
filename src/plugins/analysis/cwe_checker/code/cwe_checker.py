'''
This plugin implements a wrapper around the BAP plugin cwe_checker, which checks ELF executables for
several CWEs (Common Weakness Enumeration). Please refer to cwe_checkers implementation for further information.
Please note that these checks are heuristics and the checks are static.
This means that there are definitely false positives and false negatives. The objective of this
plugin is to find potentially interesting binaries that deserve a deep manual analysis or intensive fuzzing.

As the plugin depends on BAP, it depends on BAP's lifting capabilities. Currently, BAP
lifts to the following architectures:
- Intel x86 (32 and 64 bits)
- ARM
- PowerPC
- Mips
'''
import json
import logging
from collections import defaultdict

from common_helper_process import execute_shell_command_get_return_code
from helperFunctions.docker import run_docker_container

from analysis.PluginBase import AnalysisBasePlugin

TIMEOUT_IN_SECONDS = 600  # 10 minutes
DOCKER_IMAGE = 'fkiecad/cwe_checker:latest'


class AnalysisPlugin(AnalysisBasePlugin):
    '''
    This class implements the FACT Python wrapper for the BAP plugin cwe_checker.
    '''
    NAME = 'cwe_checker'
    DESCRIPTION = 'This plugin checks ELF binaries for several CWEs (Common Weakness Enumeration) like'\
                  'CWE-243 (Creation of chroot Jail Without Changing Working Directory) and'\
                  'CWE-676 (Use of Potentially Dangerous Function).'\
                  'Due to the nature of static analysis, this plugin may run for a long time.'
    DEPENDENCIES = ['cpu_architecture', 'file_type']
    VERSION = '0.5.0'
    MIME_WHITELIST = ['application/x-executable', 'application/x-object', 'application/x-sharedlib']
    SUPPORTED_ARCHS = ['arm', 'x86', 'x64', 'mips', 'ppc']

    def __init__(self, plugin_administrator, config=None, recursive=True, timeout=TIMEOUT_IN_SECONDS + 30):
        self.config = config
        if not self._check_docker_installed():
            raise RuntimeError('Docker is not installed.')
        self._log_version_string()
        super().__init__(plugin_administrator, config=config, plugin_path=__file__, recursive=recursive, timeout=timeout)

    @staticmethod
    def _check_docker_installed():
        _, return_code = execute_shell_command_get_return_code('docker -v')
        return return_code == 0

    def _log_version_string(self):
        output = self._run_cwe_checker_to_get_version_string()
        if output is None:
            logging.error('Could not get version string from cwe_checker.')
        else:
            logging.info('Version is {}'.format(str(output)))
        return output

    @staticmethod
    def _run_cwe_checker_to_get_version_string():
        return run_docker_container(DOCKER_IMAGE, timeout=60,
                                    command='--version')

    @staticmethod
    def _run_cwe_checker_in_docker(file_object):
        return run_docker_container(DOCKER_IMAGE, timeout=TIMEOUT_IN_SECONDS,
                                    command='/input --json --quiet',
                                    mount=('/input', file_object.file_path))

    @staticmethod
    def _parse_cwe_checker_output(output):
        tmp = defaultdict(list)
        j_doc = json.loads(output)
        for warning in j_doc:
            tmp[warning['name']] = tmp[warning['name']] + [warning, ]

        res = {}
        for key, values in tmp.items():
            tmp_list = []
            plugin_version = None
            for hit in values:
                tmp_list.append(hit['description'])
                if not plugin_version:
                    plugin_version = hit['version']
            res[key] = {'plugin_version': plugin_version,
                        'warnings': tmp_list}

        return res

    def _is_supported_arch(self, file_object):
        arch_type = file_object.processed_analysis['file_type']['full'].lower()
        return any(supported_arch in arch_type for supported_arch in self.SUPPORTED_ARCHS)

    def _do_full_analysis(self, file_object):
        output = self._run_cwe_checker_in_docker(file_object)
        if output is not None:
            try:
                cwe_messages = self._parse_cwe_checker_output(output)
                file_object.processed_analysis[self.NAME] = {'full': cwe_messages, 'summary': list(cwe_messages.keys())}
            except json.JSONDecodeError:
                logging.error('cwe_checker execution failed: {}\nUID: {}'.format(output, file_object.uid))
                file_object.processed_analysis[self.NAME] = {'summary': []}
        else:
            logging.error('Timeout or error during cwe_checker execution.\nUID: {}'.format(file_object.uid))
            file_object.processed_analysis[self.NAME] = {'summary': []}
        return file_object

    def process_object(self, file_object):
        '''
        This function handles only ELF executables. Otherwise it returns an empty dictionary.
        It calls the cwe_checker docker container.
        '''
        if not self._is_supported_arch(file_object):
            logging.debug('{}\'s arch is not supported ({})'.format(
                file_object.file_path,
                file_object.processed_analysis['cpu_architecture']['summary']))
            file_object.processed_analysis[self.NAME] = {'summary': []}
        else:
            file_object = self._do_full_analysis(file_object)

        return file_object
