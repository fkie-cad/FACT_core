import logging
import re
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

    def _parse_linter_output(self, output):  # throws TypeError on bad line
        issues = []
        for message in output.splitlines()[:-2]:
            try:
                remaining_line, issue_code = self._strip_file_path_and_extract_code(message)
                remaining_line, line_number, column = self._extract_line_and_column(remaining_line)
                issues.append(dict(line=line_number, column=column, symbol=issue_code, message=remaining_line))
            except IndexError:
                logging.debug('js linter caused error on line: {}'.format(message))

        return {'full': issues, 'summary': list(set(issue['symbol'] for issue in issues))}

    @staticmethod
    def _strip_file_path_and_extract_code(line):
        colon_separated = line.split(':')
        line_without_path = ':'.join(colon_separated[1:])

        split_by_message_end = line_without_path.split('. ')
        line_without_path_and_code = '. '.join(split_by_message_end[:-1])

        return line_without_path_and_code, split_by_message_end[-1].strip('() ')

    @staticmethod
    def _extract_line_and_column(line):
        comma_separated = line.split(',')
        line_number = comma_separated[0].strip()[5:]
        column = comma_separated[1].strip()[4:]
        return ','.join(comma_separated[2:]).strip(), int(line_number), int(column)
