import logging
import re
import sys
from pathlib import Path
from tempfile import NamedTemporaryFile

from common_helper_process import execute_shell_command_get_return_code
from docker.errors import DockerException
from requests.exceptions import ReadTimeout

from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.docker import run_docker_container

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

    def __init__(self, plugin_administrator, config=None, recursive=True, offline_testing=False):
        self.config = config
        if not self._check_docker_installed():
            raise RuntimeError('Docker is not installed.')
        super().__init__(plugin_administrator, config=config, plugin_path=__file__, recursive=recursive, offline_testing=offline_testing)

    @staticmethod
    def _check_docker_installed():
        _, return_code = execute_shell_command_get_return_code('docker -v')
        return return_code == 0

    @staticmethod
    def _get_script_type(file_object, linguist_output):
        if 'language' in linguist_output:
            file_object.processed_analysis['file_type']['linguist'] = linguist_output
            match = re.search(r'language:\s*(\w+)', linguist_output)
            if match:
                return match.groups()[0].lower()
            raise NotImplementedError('Unsupported script type, not correctly detected or not a script at all')
        return None

    def process_object(self, file_object):
        '''
        After only receiving text files thanks to the whitelist, we try to detect the correct scripting language
        and then call a linter if a supported language is detected
        '''
        try:
            with NamedTemporaryFile() as fp:
                fp.write(file_object.binary)
                fp.seek(0)
                container_path = '/repo/{}'.format(file_object.file_name)
                output = run_docker_container('crazymax/linguist', 60, container_path, reraise=True,
                                              mount=(container_path, fp.name), label=self.NAME)
            script_type = self._get_script_type(file_object, output)
            issues = self.SCRIPT_TYPES[script_type]['linter']().do_analysis(file_object.file_path)
            if not issues:
                file_object.processed_analysis[self.NAME] = {'summary': []}
            else:
                file_object.processed_analysis[self.NAME] = {'full': sorted(issues, key=lambda k: k['symbol']),
                                                             'summary': ['Warnings in {} script'.format(script_type)]}
        except (NotImplementedError, UnicodeDecodeError, KeyError):
            logging.debug('[{}] {} is not a supported script.'.format(self.NAME, file_object.file_name))
            file_object.processed_analysis[self.NAME] = {'summary': [], 'warning': 'Unsupported script type'}
        except ReadTimeout:
            file_object.processed_analysis[self.NAME] = {'summary': [], 'warning': 'Analysis timed out'}
        except (DockerException, IOError):
            file_object.processed_analysis[self.NAME] = {'summary': [], 'warning': 'Error during analysis'}
        return file_object
