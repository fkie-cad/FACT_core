import logging
import sys
from pathlib import Path

from analysis.PluginBase import AnalysisBasePlugin
from objects.file import FileObject

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
    TODO implement proper language detection
    TODO implement additional linters (ruby, perl, php)
    '''
    NAME = 'source_code_analysis'
    DESCRIPTION = 'This plugin implements static code analysis for multiple scripting languages'
    DEPENDENCIES = ['file_type']
    VERSION = '0.4'
    MIME_WHITELIST = ['text/']
    SCRIPT_TYPES = {
        'shell': {'mime': 'shell', 'shebang': 'sh', 'ending': '.sh', 'linter': shell_linter.ShellLinter},
        'lua': {'mime': 'luascript', 'shebang': 'lua', 'ending': '.lua', 'linter': lua_linter.LuaLinter},
        'javascript': {'mime': 'java', 'shebang': 'java', 'ending': '.js', 'linter': js_linter.JavaScriptLinter},
        'python': {'mime': 'python', 'shebang': 'python', 'ending': '.py', 'linter': python_linter.PythonLinter}
    }

    def __init__(self, plugin_adminstrator, config=None, recursive=True, offline_testing=False):
        self.config = config
        super().__init__(plugin_adminstrator, config=config, plugin_path=__file__, recursive=recursive, offline_testing=offline_testing)

    def _determine_script_type(self, file_object: FileObject):
        '''
        Indicators:
        1. file_type full includes shell, python etc.
        2. shebang #!/bin/sh, #!/usr/bin/env python etc.
        3. file ending *.sh, *.py etc.
        '''
        full_file_type = file_object.processed_analysis['file_type']['full'].lower()
        for script_type in self.SCRIPT_TYPES:

            if self.SCRIPT_TYPES[script_type]['mime'] in full_file_type.lower():
                return script_type

            first_line = file_object.binary.decode().splitlines(keepends=False)[0]
            if first_line.find(self.SCRIPT_TYPES[script_type]['shebang']) >= 0:
                return script_type

            if file_object.file_name.endswith(self.SCRIPT_TYPES[script_type]['ending']):
                return script_type

        raise NotImplementedError('Unsupported script type, not correctly detected or not a script at all')

    def process_object(self, file_object):
        '''
        After only receiving text files thanks to the whitelist, we try to detect the correct scripting language
        and then call a linter if a supported language is detected
        '''
        try:
            script_type = self._determine_script_type(file_object)
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
