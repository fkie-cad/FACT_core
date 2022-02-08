# abort shellcheck in case we encountered something strange aka lua, js, or something different
# -> Fix any mentioned problems and try again. (1072)
# -> Couldn't parse this function. (1073)
# -> This { is literal. Check expression (missing ;/\\n?) or quote it. (1083)
# -> Parsing stopped here. Is this keyword correctly matched up? (1089)

import json
import logging
import subprocess
from subprocess import PIPE, STDOUT


class ShellLinter:
    '''
    Wrapper for shellcheck shell linter
    '''
    def do_analysis(self, file_path):
        shellcheck_p = subprocess.run(
            'shellcheck --format=json {}'.format(file_path),
            shell=True,
            stdout=PIPE,
            stderr=STDOUT,
            universal_newlines=True,
        )

        if shellcheck_p.stdout == 2:
            logging.debug('Failed to execute shellcheck:\n{}'.format(shellcheck_p.stdout))
            return list()

        try:
            shellcheck_json = json.loads(shellcheck_p.stdout)
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
