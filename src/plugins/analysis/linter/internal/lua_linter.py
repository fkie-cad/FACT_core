import logging
import subprocess
from pathlib import Path
from subprocess import PIPE, STDOUT

CONFIG_FILE_PATH = Path(Path(__file__).parent, 'config', '.luacheckrc')


class LuaLinter:
    '''
    Wrapper for luacheck luascript linter
    '''
    def do_analysis(self, file_path):
        luacheck_p = subprocess.run(
            'luacheck -q --ranges --config  {} {}'.format(CONFIG_FILE_PATH, file_path),
            shell=True,
            stdout=PIPE,
            stderr=STDOUT,
            text=True,
        )
        return self._parse_linter_output(luacheck_p.stdout)

    def _parse_linter_output(self, output):
        '''
        https://luacheck.readthedocs.io/en/stable/warnings.html
        ignore_cases = ['(W611)', '(W612)', '(W613)', '(W614)', '(W621)', '(W631)']
        '''
        issues = list()
        for line in output.splitlines():
            try:
                line_number, columns, code_and_message = self._split_issue_line(line)
                code, message = self._separate_message_and_code(code_and_message)
                if not code.startswith('(W6'):
                    issues.append({
                        'line': int(line_number),
                        'column': self._get_first_column(columns),
                        'symbol': code,
                        'message': message
                    })
                else:
                    pass
            except (IndexError, ValueError) as e:
                logging.warning('Lualinter failed to parse line: {}\n{}'.format(line, e))

        return issues

    @staticmethod
    def _split_issue_line(line):
        split_by_colon = line.split(':')
        return split_by_colon[1], split_by_colon[2], ':'.join(split_by_colon[3:]).strip()

    @staticmethod
    def _separate_message_and_code(message_string):
        return message_string[1:5], message_string[6:].strip()

    @staticmethod
    def _get_first_column(columns):
        return int(columns.split('-')[0])
