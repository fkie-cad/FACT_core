import logging
from pathlib import Path

from common_helper_process import execute_shell_command

CONFIG_FILE_PATH = Path(Path(__file__).parent, 'config', '.jshintrc')


class JavaScriptLinter:
    '''
    Wrapper for jshint javascript linter
    '''
    def do_analysis(self, file_path):
        linter_output = execute_shell_command('jshint --config={} --verbose {}'.format(CONFIG_FILE_PATH, file_path))
        return self._parse_linter_output(linter_output)

    def _parse_linter_output(self, linter_output):
        issues = []
        for issue in linter_output.splitlines()[:-2]:
            try:
                remaining_line = self._strip_file_path(issue)
                remaining_line, issue_code = self._extract_issue_code(remaining_line)
                remaining_line, line_number, column = self._extract_line_and_column(remaining_line)
                issues.append(dict(line=line_number, column=column, symbol=issue_code, message=remaining_line))
            except (IndexError, ValueError) as error:
                logging.warning('jshint line was not correctly parsed: {}\n{}'.format(issue, str(error)))

        return issues

    @staticmethod
    def _strip_file_path(line):
        colon_separated = line.split(':')
        return ':'.join(colon_separated[1:])

    @staticmethod
    def _extract_issue_code(line):
        bracket_separated = line.split('(')
        code_part = bracket_separated[-1]
        return '('.join(bracket_separated[:-1]), code_part.strip(' )')

    @staticmethod
    def _extract_line_and_column(line):
        comma_separated = line.split(',')
        line_number = comma_separated[0].strip()[5:]
        column = comma_separated[1].strip()[4:]
        return ','.join(comma_separated[2:]).strip(), int(line_number), int(column)
