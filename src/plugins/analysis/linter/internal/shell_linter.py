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
        linter_output, return_code = execute_shell_command_get_return_code('shellcheck --format=json {}'.format(file_path))

        if return_code == 2:
            logging.debug('Failed to execute shellcheck:\n{}'.format(linter_output))
            return list()

        try:
            shellcheck_json = json.loads(linter_output)
        except json.JSONDecodeError:
            return list()

        return self._extract_relevant_warnings(shellcheck_json)

    @staticmethod
    def _extract_relevant_warnings(shellcheck_json):
        issues = list()
        for issue in shellcheck_json:
            if issue['level'] in ['warning', 'error']:
                issues.append({
                    'type': issue['level'],
                    'line': issue['line'],
                    'column': issue['column'],
                    'symbol': str(issue['code']),
                    'message': issue['message']
                })
        return issues
