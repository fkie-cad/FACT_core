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
import logging
from collections import defaultdict

import sexpdata
from common_helper_process import execute_shell_command_get_return_code

from analysis.PluginBase import AnalysisBasePlugin

BAP_TIMEOUT = 10  # in minutes
DOCKER_IMAGE = 'fkiecad/cwe_checker:latest'


class CweWarning:

    def __init__(self, name, plugin_version, warning):
        self.name = name
        self.plugin_version = plugin_version
        self.warning = warning


class CweWarningParser:
    '''
    Parses a CWE warning emitted by the BAP plugin CweChecker
    '''

    @staticmethod
    def _remove_color(string):
        '''
        Removes 'color' from string
        See https://stackoverflow.com/questions/287871/print-in-terminal-with-colors/293633#293633
        '''
        return string.replace('\x1b[0m', '').strip()

    def parse(self, warning):
        try:
            splitted_line = warning.split('WARN')
            cwe_warning = splitted_line[1].replace(
                'u32', '').replace(':', '')

            cwe_name = self._remove_color(cwe_warning.split(')')[0]) + ')'
            cwe_name = cwe_name.split('{')[0].strip() + ' ' + cwe_name.split('}')[1].strip()

            plugin_version = cwe_warning.split('{')[1].split('}')[0]

            cwe_message = ')'.join(cwe_warning.split(')')[1:])
            cwe_message = cwe_message.replace('.', '').replace('32u', '')

            return CweWarning(cwe_name, plugin_version, cwe_message)
        except IndexError as error:
            logging.error('IndexError while parsing CWE warning: {}.'.format(str(error)))
            return None


class AnalysisPlugin(AnalysisBasePlugin):
    '''
    This class implements the FACT Python wrapper for the BAP plugin cwe_checker.
    '''
    NAME = 'cwe_checker'
    DESCRIPTION = 'This plugin checks ELF binaries for several CWEs (Common Weakness Enumeration) like'\
                  'CWE-243 (Creation of chroot Jail Without Changing Working Directory) and'\
                  'CWE-676 (Use of Potentially Dangerous Function). Internally it uses BAP 1.5, which currently supports ARM, x86/x64, PPC and MIPS.'\
                  'Due to the nature of static analysis, this plugin may run for a long time.'
    DEPENDENCIES = ['cpu_architecture', 'file_type']
    VERSION = '0.3.4'
    MIME_WHITELIST = ['application/x-executable', 'application/x-object', 'application/x-sharedlib']
    SUPPORTED_ARCHS = ['arm', 'x86', 'x64', 'mips', 'ppc']

    def __init__(self, plugin_adminstrator, config=None, recursive=True, timeout=BAP_TIMEOUT * 60 + 10):
        self.config = config
        if not self._check_docker_installed():
            raise RuntimeError('Docker is not installed.')
        self._module_versions = self._get_module_versions()
        logging.info('Module versions are {}'.format(str(self._module_versions)))
        super().__init__(plugin_adminstrator, config=config, plugin_path=__file__, recursive=recursive, timeout=timeout)

    @staticmethod
    def _check_docker_installed():
        _, return_code = execute_shell_command_get_return_code('docker -v')
        return return_code == 0

    def _get_module_versions(self):
        bap_command = self._build_bap_command_for_modules_versions()
        output, return_code = execute_shell_command_get_return_code(bap_command)
        if return_code != 0:
            logging.error('Could not get module versions from Bap plugin: {} ({}). I tried the following command: {}'.format(
                return_code, output, bap_command))
            return {}
        return self._parse_module_versions(output)

    @staticmethod
    def _parse_module_versions(bap_output):
        module_versions = {}
        for line in bap_output.splitlines():
            if 'module_versions:' in line:
                version_sexp = line.split('module_versions:')[-1].strip()
                module_versions = dict(sexpdata.loads(version_sexp))
        return module_versions

    @staticmethod
    def _build_bap_command_for_modules_versions():
        # unfortunately, there must be a dummy file passed to BAP, I chose /bin/true because it is damn small
        return 'docker run --rm {} bap /bin/true --pass=cwe-checker --cwe-checker-module_versions=true'.format(DOCKER_IMAGE)

    @staticmethod
    def _build_bap_command(file_object):
        return 'timeout --signal=SIGKILL {}m docker run --rm -v {}:/tmp/input {} bap /tmp/input '\
               '--pass=cwe-checker --cwe-checker-config=/home/bap/cwe_checker/src/config.json'.format(BAP_TIMEOUT, file_object.file_path, DOCKER_IMAGE)

    @staticmethod
    def _parse_bap_output(output):
        tmp = defaultdict(list)
        cwe_parser = CweWarningParser()

        for line in output.splitlines():
            if 'WARN' in line:
                cwe_warning = cwe_parser.parse(line)
                tmp[cwe_warning.name].append(cwe_warning)

        res = {}
        for key, values in tmp.items():
            tmp_list = []
            plugin_version = None
            for cwe in values:
                tmp_list.append(cwe.warning)
                if not plugin_version:
                    plugin_version = cwe.plugin_version
            res[key] = {'plugin_version': plugin_version,
                        'warnings': tmp_list}

        return res

    def _is_supported_arch(self, file_object):
        arch_type = file_object.processed_analysis['file_type']['full'].lower()
        return any(supported_arch in arch_type for supported_arch in self.SUPPORTED_ARCHS)

    def _do_full_analysis(self, file_object):
        bap_command = self._build_bap_command(file_object)
        output, return_code = execute_shell_command_get_return_code(
            bap_command)
        if return_code in [0, 124, 128 + 9]:
            cwe_messages = self._parse_bap_output(output)
            file_object.processed_analysis[self.NAME] = {'full': cwe_messages, 'summary': list(cwe_messages.keys())}
            if return_code in [124, 128 + 9]:
                logging.warning('CWE-Checker timed out on {}. Warnings might not be complete.'.format(file_object.get_uid()))
                file_object.processed_analysis[self.NAME]['warning'] = 'Analysis timed out. Warnings might not be complete.'
        else:
            logging.error('Could not communicate with Bap plugin: {} ({})\nUID: {}'.format(return_code, output, file_object.get_uid()))
            file_object.processed_analysis[self.NAME] = {'summary': []}
        return file_object

    def process_object(self, file_object):
        '''
        This function handles only ELF executable. Otherwise it returns an empty dictionary.
        It calls the external BAP plugin cwe_checker.
        '''
        if not self._is_supported_arch(file_object):
            logging.debug('{}\'s arch is not supported ({})'.format(
                file_object.file_path,
                file_object.processed_analysis['cpu_architecture']['summary']))
            file_object.processed_analysis[self.NAME] = {'summary': []}
        else:
            file_object = self._do_full_analysis(file_object)

        return file_object
