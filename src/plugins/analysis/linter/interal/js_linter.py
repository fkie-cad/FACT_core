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

    def _parse_linter_output(self, output):
        res = {}
        for line in output.splitlines()[:-2]:
            extract_error_code = line[-6:].strip()
            line = line[:-6].rstrip()
            extract_message = line.split('. ')[0].split(':')[1].split(',')[2].strip()
            extract_line = line.split('. ')[0].split(':')[1].split(',')[0].split()[1].strip()
            extract_message = self._remove_noise_from_message(extract_message).strip()
            temp_res = '@{}: {} {}'.format(extract_line, extract_message, extract_error_code)
            if extract_message in res:
                res[extract_message] = res[extract_message] + [temp_res]
            else:
                res[extract_message] = [temp_res]
        return {'full': res, 'summary': list(res.keys())}

    def _remove_noise_from_message(self, extract_message):
        extract_message = self._replace_noise(extract_message, r'\s\'.{0,3}\'.$', replacement='.')
        extract_message = self._replace_noise(extract_message, r'\s"\b[a-zA-Z\s_0-9]*\b"')
        extract_message = self._replace_noise(extract_message, r'\s\'\b[a-zA-Z\s_0-9]*\b\'')
        extract_message = self._replace_noise(extract_message, r'"\b[a-zA-Z\s_0-9]*\b"')
        extract_message = self._replace_noise(extract_message, r'\'\b[a-zA-Z\s_0-9]*\b\'')
        extract_message = self._replace_noise(extract_message, r'on line', group_expression=r'\son\sline\s[0-9]*')
        extract_message = self._replace_noise(extract_message, r'\'\$?[a-zA-Z0-9]*\'')
        return extract_message

    @staticmethod
    def _replace_noise(extract_message, search_expression, group_expression=None, replacement=''):
        if re.search(search_expression, extract_message):
            remove_var_name = re.search(group_expression if group_expression else search_expression, extract_message).group(0)
            extract_message = extract_message.replace(remove_var_name, replacement)
        return extract_message
