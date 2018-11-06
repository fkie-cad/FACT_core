# TODO Implement proper view
# - group messages (+/-)
# - colors (error in red, warnings in yellow)
# TODO implement proper language detection
# TODO implement additional linters (ruby, perl, php)

import logging

from analysis.PluginBase import AnalysisBasePlugin
from objects.file import FileObject
from ..interal.python_linter import PythonLinter
from ..interal.shell_linter import ShellLinter
from ..interal.js_linter import JavaScriptLinter
from ..interal.lua_linter import LuaLinter


class AnalysisPlugin(AnalysisBasePlugin):
    '''
    This class implements the FACT wrapper for multiple linters including
    - shellcheck (shell)
    - pylint (python)
    '''
    NAME = 'source_code_analysis'
    DESCRIPTION = 'This plugin implements static code analysis for multiple scripting languages'
    DEPENDENCIES = ['file_type']
    VERSION = '0.2'
    MIME_WHITELIST = ['text/*']
    SCRIPT_TYPES = {
        'shell': {'mime': 'shell', 'shebang': 'sh', 'ending': '.sh', 'linter': ShellLinter},
        'lua': {'mime': 'luascript', 'shebang': 'lua', 'ending': '.lua', 'linter': LuaLinter},
        'javascript': {'mime': 'java', 'shebang': 'java', 'ending': '.js', 'linter': JavaScriptLinter},
        'python': {'mime': 'python', 'shebang': 'python', 'ending': '.py', 'linter': PythonLinter}
    }

    def __init__(self, plugin_adminstrator, config=None, recursive=True, offline_testing=False):
        self.config = config
        super().__init__(plugin_adminstrator, config=config, plugin_path=__file__, recursive=recursive, offline_testing=offline_testing)

    def _determine_script_type(self, file_object: FileObject):
        '''
        Indicators:
        1. file_type full includes shell, python
        2. shebang #!/bin/sh, #!/usr/bin/env python
        3. file ending *.sh, *.py
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
        except NotImplementedError:
            logging.debug('[{}] {} is not a shell script.'.format(self.NAME, file_object.file_path))
            file_object.processed_analysis[self.NAME] = {'summary': []}
        else:
            linter = self.SCRIPT_TYPES[script_type]['linter']()
            report = linter.do_analysis(file_object.file_path)
            file_object.processed_analysis[self.NAME] = report
        return file_object
