# abort shellcheck in case we encountered something strange aka lua, js, or something different
# -> Fix any mentioned problems and try again. (1072)
# -> Couldn't parse this function. (1073)
# -> This { is literal. Check expression (missing ;/\\n?) or quote it. (1083)
# -> Parsing stopped here. Is this keyword correctly matched up? (1089)

import json
import logging

from common_helper_process import execute_shell_command_get_return_code


class ShellLinter:
    '''
    Wrapper for shellcheck shell linter
    '''
    def do_analysis(self, file_path):
        shellcheck_command = 'shellcheck --format=json {}'.format(file_path)
        linter_output, return_code = execute_shell_command_get_return_code(shellcheck_command)

        if return_code == 2:
            logging.debug('Failed to execute shellcheck:\n{}'.format(linter_output))
            return {'summary': []}

        return self._parse_shellcheck_output(linter_output)

    def _parse_shellcheck_output(self, linter_output):
        try:
            shellcheck_json = json.loads(linter_output)
        except json.JSONDecodeError:
            return {'summary': [], 'failure': 'shellcheck output could not be parsed', 'output': linter_output}

        result = self._extract_relevant_warnings(shellcheck_json)

        if self._detect_filetype_mismatch:
            return {}

        return {'full': result, 'summary': list(result.keys())}

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
