'''
TODO
'''
from collections import defaultdict
import logging
import re
import os
import json

from common_helper_process import execute_shell_command_get_return_code
from analysis.PluginBase import AnalysisBasePlugin

# TODO: implement more linters!


class AnalysisPlugin(AnalysisBasePlugin):
    '''
    This class implements the FACT Python wrapper for the shell linter shellcheck.
    '''
    NAME = "code_analysis_shell_script"
    DESCRIPTION = "This plugin implements static code analysis of shell scripts using the shell script linter shellcheck"
    DEPENDENCIES = ['file_type']
    VERSION = '0.1'
    # FIXME: implement proper language detection of lua, python, js, ...
    SUPPORTED_TYPES = ['shell', 'script', 'ascii']

    def __init__(self, plugin_adminstrator, config=None, recursive=True):
        self.config = config
        super().__init__(plugin_adminstrator, config=config,
                         plugin_path=__file__, recursive=recursive)

    def _build_shellcheck_command(self, file_object):
        shellcheck_command = "shellcheck --format=json {}".format(file_object.file_path)
        return shellcheck_command

    def _parse_shellcheck_output(self, output):
        res = {}
        shellcheck_json = json.loads(output)
        for warning in shellcheck_json:
            # we do not care about style and code warnings
            if warning["level"] == "warning" or warning["level"] == "error":
                line = warning['line']
                code = str(warning['code'])
                level = warning['level']
                message = warning['message']
                temp_res = "@{}: {} {} ({})".format(line, level, message, code)
                if code in res:
                    res[code] = res[code] + [temp_res]
                else:
                    res[code] = [temp_res]

        # TODO/FIXME: implement proper language detection in the first place
        # abort in case we encountered something strange aka lua, js, or something different
        # -> Fix any mentioned problems and try again. (1072)
        # -> Couldn't parse this function. (1073)
        # -> This { is literal. Check expression (missing ;/\\n?) or quote it. (1083)
        # -> Parsing stopped here. Is this keyword correctly matched up? (1089)
        if ("1072" in res and "1073" in res) or ("1083" in res and "1089" in res):
            return {}

        return res

    def _is_supported_file_type(self, file_object):
        file_type = file_object.processed_analysis['file_type']['full'].lower()
        for t in self.SUPPORTED_TYPES:
            if t in file_type:
                return True
        return False

    def _do_analysis(self, file_object):
        shellcheck_command = self._build_shellcheck_command(file_object)
        output, return_code = execute_shell_command_get_return_code(
            shellcheck_command)
        # see https://github.com/koalaman/shellcheck/blob/master/shellcheck.hs for error codes
        if return_code == 2:
            logging.error("[%s] Could not communicate with shellcheck: %i (%s).",
                          self.NAME, return_code, output)
            file_object.processed_analysis[self.NAME] = {'summary': []}
        else:
            shellcheck_warnings = self._parse_shellcheck_output(output)
            file_object.processed_analysis[self.NAME] = {'full': shellcheck_warnings,
                                                         'summary': list(shellcheck_warnings.keys())}
        return file_object

    def process_object(self, file_object):
        '''
        This function handles only shell scripts. Otherwise it returns an empty dictionary.
        It calls the external linter shellcheck.
        '''
        if not self._is_supported_file_type(file_object):
            logging.debug("[%s] %s is not a shell script.",
                          self.NAME, file_object.file_path)
            file_object.processed_analysis[self.NAME] = {'summary': []}
        else:
            logging.debug("[%s] shellcheck analysis of %s." % (self.NAME, file_object.file_path))
            file_object = self._do_analysis(file_object)

        return file_object

    # TODO: Implement proper view
    # - group messages (+/-)
    # - colors (error in red, warnings in yellow)
