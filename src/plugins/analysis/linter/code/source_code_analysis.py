# TODO: implement more linters!
# TODO: Implement proper view
# - group messages (+/-)
# - colors (error in red, warnings in yellow)
# FIXME: implement proper language detection of lua, python, js, ...
# TODO/FIXME: implement proper language detection in the first place
# abort shellcheck in case we encountered something strange aka lua, js, or something different
# -> Fix any mentioned problems and try again. (1072)
# -> Couldn't parse this function. (1073)
# -> This { is literal. Check expression (missing ;/\\n?) or quote it. (1083)
# -> Parsing stopped here. Is this keyword correctly matched up? (1089)

import json
import logging

from common_helper_process import execute_shell_command_get_return_code

from analysis.PluginBase import AnalysisBasePlugin
from objects.file import FileObject


class ShellLinter:
    '''
    Wrapper for shellcheck shell linter
    '''
    def do_analysis(self, file_path):
        shellcheck_command = 'shellcheck --format=json {}'.format(file_path)
        linter_output, return_code = execute_shell_command_get_return_code(shellcheck_command)

        if return_code == 2:
            logging.debug('Could not communicate with shellcheck:\n{}'.format(linter_output))
            return {'summary': []}
        else:
            shellcheck_warnings = self._parse_shellcheck_output(linter_output)
            return {'full': shellcheck_warnings, 'summary': list(shellcheck_warnings.keys())}

    def _parse_shellcheck_output(self, linter_output):
        try:
            shellcheck_json = json.loads(linter_output)
        except json.JSONDecodeError:
            return {'summary': [], 'failure': 'shellcheck output could not be parsed', 'output': linter_output}

        result = self._extract_relevant_warnings(shellcheck_json)

        if self._detect_filetype_mismatch:
            return {}

        return result

    @staticmethod
    def _extract_relevant_warnings(shellcheck_json):
        result = {}
        for warning in shellcheck_json:
            # we do not care about style and code warnings
            if warning['level'] == 'warning' or warning['level'] == 'error':
                line = warning['line']
                code = str(warning['code'])
                level = warning['level']
                message = warning['message']
                temp_res = '@{}: {} {} ({})'.format(line, level, message, code)
                if code not in result:
                    result[code] = []
                result[code] = result[code].append(temp_res)
        return result

    @staticmethod
    def _detect_filetype_mismatch(result):
        return ('1072' in result and '1073' in result) or ('1083' in result and '1089' in result)


class PythonLinter:
    '''
    Wrapper for pylint python linter
    '''
    def do_analysis(self, file_path):
        return {'summary': []}


class AnalysisPlugin(AnalysisBasePlugin):
    '''
    This class implements the FACT wrapper for multiple linters including
    - shellcheck (shell)
    - pylint (python)
    '''
    NAME = 'source_code_analysis'
    DESCRIPTION = 'This plugin implements static code analysis for multiple scripting languages'
    DEPENDENCIES = ['file_type']
    VERSION = '0.2'
    MIME_WHITELIST = ['text/*']
    SCRIPT_TYPES = {
        'shell': {'mime': 'shell', 'shebang': 'sh', 'ending': '.sh', 'linter': ShellLinter},
        'python': {'mime': 'python', 'shebang': 'python', 'ending': '.py'}
    }

    def __init__(self, plugin_adminstrator, config=None, recursive=True, offline_testing=False):
        self.config = config
        super().__init__(plugin_adminstrator, config=config, plugin_path=__file__, recursive=recursive, offline_testing=offline_testing)

    def _determine_script_type(self, file_object: FileObject):
        '''
        Indicators:
        1. file_type full includes shell, python
        2. shebang #!/bin/sh, #!/usr/bin/env python
        3. file ending *.sh, *.py
        '''
        full_file_type = file_object.processed_analysis['file_type']['full'].lower()
        for script_type in self.SCRIPT_TYPES:

            if self.SCRIPT_TYPES[script_type]['mime'] in full_file_type.lower():
                return script_type

            first_line = file_object.binary.decode().splitlines(keepends=False)[0]
            if first_line.find(self.SCRIPT_TYPES[script_type]['shebang']) >= 0:
                return script_type

            if file_object.file_name.endswith(self.SCRIPT_TYPES[script_type]['ending']):
                return script_type

        raise NotImplementedError('Unsupported script type, not correctly detected or not a script at all')

    def process_object(self, file_object):
        '''
        This function handles only shell scripts. Otherwise it returns an empty dictionary.
        It calls the external linter shellcheck.
        '''
        try:
            script_type = self._determine_script_type(file_object)
        except NotImplementedError:
            logging.debug('[{}] {} is not a shell script.'.format(self.NAME, file_object.file_path))
            file_object.processed_analysis[self.NAME] = {'summary': []}
        else:
            linter = self.SCRIPT_TYPES[script_type]['linter']()
            report = linter.do_analysis(file_object.file_path)
            file_object.processed_analysis[self.NAME] = report
        return file_object
