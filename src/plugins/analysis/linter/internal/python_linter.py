import json
import logging

from common_helper_process import execute_shell_command


class PythonLinter:
    '''
    Wrapper for pylint python linter
    '''
    def do_analysis(self, file_path):
        pylint_output = execute_shell_command(f'pylint --output-format=json {file_path}')
        try:
            pylint_json = json.loads(pylint_output)
        except json.JSONDecodeError:
            logging.warning(f'Failed to execute pylint:\n{pylint_output}', exc_info=True)
            return []

        return self._extract_relevant_warnings(pylint_json)

    @staticmethod
    def _extract_relevant_warnings(pylint_json):
        issues = []
        for issue in pylint_json:
            if issue['type'] in ['error', 'warning']:
                for unnecessary_information in ['module', 'obj', 'path', 'message-id']:
                    issue.pop(unnecessary_information)
                issues.append(issue)
        return issues
