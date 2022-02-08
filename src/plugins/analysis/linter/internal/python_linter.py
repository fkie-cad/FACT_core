import json
import logging
import subprocess
from subprocess import PIPE, STDOUT


class PythonLinter:
    '''
    Wrapper for pylint python linter
    '''
    def do_analysis(self, file_path):
        pylint_p = subprocess.run('pylint --output-format=json {}'.format(file_path), shell=True, stdout=PIPE, stderr=STDOUT, universal_newlines=True)
        try:
            pylint_json = json.loads(pylint_p.stdout)
        except json.JSONDecodeError:
            logging.warning('Failed to execute pylint:\n{}'.format(pylint_p.stdout))
            return list()

        return self._extract_relevant_warnings(pylint_json)

    @staticmethod
    def _extract_relevant_warnings(pylint_json):
        issues = list()
        for issue in pylint_json:
            if issue['type'] in ['error', 'warning']:
                for unnecessary_information in ['module', 'obj', 'path', 'message-id']:
                    issue.pop(unnecessary_information)
                issues.append(issue)
        return issues
