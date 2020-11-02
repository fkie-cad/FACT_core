import logging
import string
import sys
from pathlib import Path
from tempfile import NamedTemporaryFile
from subprocess import check_output

from common_helper_process import execute_shell_command_get_return_code

from analysis.PluginBase import AnalysisBasePlugin

try:
    from ..internal import js_linter, lua_linter, python_linter, shell_linter
except ImportError:
    sys.path.append(str(Path(__file__).parent.parent))
    from internal import js_linter, lua_linter, python_linter, shell_linter


class AnalysisPlugin(AnalysisBasePlugin):
    '''
    This class implements the FACT wrapper for multiple linters including
    - shellcheck (shell)
    - pylint (python)
    - jshint (javascript)
    - lua (luacheck)
    TODO Implement proper view
    TODO implement additional linters (ruby, perl, php)
    '''
    NAME = 'source_code_analysis'
    DESCRIPTION = 'This plugin implements static code analysis for multiple scripting languages'
    DEPENDENCIES = ['file_type']
    VERSION = '0.5'
    MIME_WHITELIST = ['text/']
    SCRIPT_TYPES = {
        'shell': {'mime': 'shell', 'shebang': 'sh', 'ending': '.sh', 'linter': shell_linter.ShellLinter},
        'lua': {'mime': 'luascript', 'shebang': 'lua', 'ending': '.lua', 'linter': lua_linter.LuaLinter},
        'javascript': {'mime': 'java', 'shebang': 'java', 'ending': '.js', 'linter': js_linter.JavaScriptLinter},
        'python': {'mime': 'python', 'shebang': 'python', 'ending': '.py', 'linter': python_linter.PythonLinter}
    }

    def __init__(self, plugin_adminstrator, config=None, recursive=True, offline_testing=False):
        self.config = config
        if not self._check_docker_installed():
            raise RuntimeError('Docker is not installed.')
        super().__init__(plugin_adminstrator, config=config, plugin_path=__file__, recursive=recursive, offline_testing=offline_testing)

    @staticmethod
    def _check_docker_installed():
        _, return_code = execute_shell_command_get_return_code('docker -v')
        return return_code == 0

    def _get_script_type(self, file_object, linguist_output):
        if 'language' in linguist_output:
            script_language = linguist_output.split('language:', 1)[1]
            script_type = script_language.translate({ord(c): None for c in string.whitespace}).lower()
            if script_type:
                file_object.processed_analysis['file_type']['linguist'] = script_type
                return script_type
            else:
                raise NotImplementedError('Unsupported script type, not correctly detected or not a script at all')

    def process_object(self, file_object):
        '''
        After only receiving text files thanks to the whitelist, we try to detect the correct scripting language
        and then call a linter if a supported language is detected
        '''
        try:
            with NamedTemporaryFile() as fp:
                fp.write(file_object.binary)
                fp.seek(0)
                linguist_command = 'docker run -t --rm -v {0}:/repo/{1} crazymax/linguist /repo/{1}'.format(fp.name, file_object.file_name)
                output = check_output(linguist_command, shell=True)
            script_type = self._get_script_type(file_object, output.decode())
        except (NotImplementedError, UnicodeDecodeError):
            logging.debug('[{}] {} is not a supported script.'.format(self.NAME, file_object.file_name))
            file_object.processed_analysis[self.NAME] = {'summary': []}
        else:
            issues = self.SCRIPT_TYPES[script_type]['linter']().do_analysis(file_object.file_path)
            if not issues:
                file_object.processed_analysis[self.NAME] = {'summary': []}
            else:
                file_object.processed_analysis[self.NAME] = {'full': sorted(issues, key=lambda k: k['symbol']),
                                                             'summary': ['Warnings in {} script'.format(script_type)]}
        return file_object
