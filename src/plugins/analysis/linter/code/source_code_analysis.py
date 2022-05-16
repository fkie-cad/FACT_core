import json
import logging
import sys
from pathlib import Path

from docker.types import Mount

from analysis.PluginBase import AnalysisBasePlugin
from config import configparser_cfg
from helperFunctions.docker import run_docker_container
from storage.fsorganizer import FSOrganizer

try:
    from internal import linters
except ImportError:
    sys.path.append(str(Path(__file__).parent.parent))
    from internal import linters


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
    VERSION = '0.6'
    MIME_WHITELIST = ['text/']
    # All linter methods must return an array of dicts.
    # These dicts must at least contain a value for the 'symbol' key.
    linter_impls = {
        'javascript':  linters.run_eslint,
        'lua':  linters.run_luacheck,
        'python': linters.run_pylint,
        'ruby': linters.run_rubocop,
        'shell': linters.run_shellcheck,
        'php': linters.run_phpstan,
    }
    FILE = __file__

    def additional_setup(self):
        self._fs_organizer = FSOrganizer(configparser_cfg)

    def process_object(self, file_object):
        '''
        After only receiving text files thanks to the whitelist, we try to detect the correct scripting language
        and then call a linter if a supported language is detected
        '''
        script_type = self._get_script_type(file_object)
        if script_type is None:
            file_object.processed_analysis[self.NAME] = {'summary': [], 'warning': 'Is not a script or language could not be detected'}
            return file_object

        script_type = script_type.lower()

        if script_type not in self.linter_impls:
            logging.debug(f'[{self.NAME}] {file_object.file_name} ({script_type}) is not a supported script.')
            file_object.processed_analysis[self.NAME] = {'summary': [], 'warning': f'Unsupported script type: {script_type}'}
            return file_object

        issues = self.linter_impls[script_type](file_object.file_path)

        if len(issues) == 0:
            file_object.processed_analysis[self.NAME] = {'summary': []}
        else:
            file_object.processed_analysis[self.NAME] = {'full': sorted(issues, key=lambda k: k['symbol']),
                                                         'summary': [f'Warnings in {script_type} script']}
        return file_object

    def _get_script_type(self, file_object):
        host_path = self._fs_organizer.generate_path_from_uid(file_object.uid)
        container_path = f'/repo/{file_object.file_name}'
        result = run_docker_container(
            'crazymax/linguist',
            combine_stderr_stdout=True,
            timeout=60,
            command=f'--json {container_path}',
            mounts=[
                Mount(container_path, host_path, type='bind'),
            ],
            logging_label=self.NAME,
        )
        output_json = json.loads(result.stdout)

        # FIXME plugins should not set the output for other plugins
        # But due to performance reasons we don't want the filetype plugin to run linguist
        file_object.processed_analysis['file_type']['linguist'] = ''.join([f'{k:<10} {str(v):<10}\n' for k, v in output_json[container_path].items()])

        script_type = output_json[container_path].get('language')

        return script_type
