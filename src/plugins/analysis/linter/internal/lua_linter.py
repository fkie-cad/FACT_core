from pathlib import Path
import re

from common_helper_process import execute_shell_command

CONFIG_FILE_PATH = Path(Path(__file__).parent, 'config', '.luacheckrc')


class LuaLinter:
    '''
    Wrapper for luacheck luascript linter
    '''
    def do_analysis(self, file_path):
        linter_output = execute_shell_command("luacheck -q --ranges --config  {} {}".format(CONFIG_FILE_PATH, file_path))
        return self._parse_linter_output(linter_output)

    @staticmethod
    def _parse_linter_output(output):
        '''
        https://luacheck.readthedocs.io/en/stable/warnings.html
        ignore_cases = ['(W611)', '(W612)', '(W613)', '(W614)', '(W621)', '(W631)']
        '''
        res = {}
        for line in output.splitlines():
            splitter = line.split(':')
            line = splitter[1]
            error_code = splitter[3].split(')')[0].lstrip(' ') + ')'
            message = splitter[3].split(')')[1]
            if re.search(r"\s'.*'", message) is not None:
                remove_var_name = re.search(r"\s'.*'", message).group(0)
                message = message.replace(remove_var_name, '')
            if re.search(r"on line", message) is not None:
                remove_line_in_msg = re.search(r"\son\sline\s[0-9]*", message).group(0)
                message = message.replace(remove_line_in_msg, '')
            temp_res = '@{}: {} {}'.format(line, message, error_code)
            if message in res:
                res[message] = res[message] + [temp_res]
            else:
                res[message] = [temp_res]
        return {'full': res, 'summary': list(res.keys())}
