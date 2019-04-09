import json
import logging

from common_helper_process import execute_shell_command


class PythonLinter:
    '''
    Wrapper for pylint python linter
    '''
    def do_analysis(self, file_path):
        pylint_output = execute_shell_command('pylint --output-format=json {}'.format(file_path))
        try:
            pylint_json = json.loads(pylint_output)
        except json.JSONDecodeError:
            logging.warning('Failed to execute pylint:\n{}'.format(pylint_output))
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
