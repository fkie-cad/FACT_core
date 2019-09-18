import json
import logging

from analysis.PluginBase import AnalysisBasePlugin
from common_helper_process import execute_shell_command_get_return_code


class AnalysisPlugin(AnalysisBasePlugin):
    '''
    This plugin determines possible input vectors of Linux ELF executables.
    Examples are:
    - network
    - stdin
    - kernel via syscalls
    Internal it utilizes a dockerized version of radare2 and is, 
    though in theory, architecture independent.
    '''
    NAME = 'input_vectors'
    DESCRIPTION = 'Determines possible input vectors of an ELF executable like stdin, network or syscalls.'
    DEPENDENCIES = ['file_type']
    VERSION = '0.1'

    def __init__(self, plugin_adminstrator, config=None, recursive=True):
        self.config = config

        super().__init__(plugin_adminstrator, config=config, recursive=recursive, plugin_path=__file__)

    @staticmethod
    def _is_supported_file_type(file_object):
        file_type = file_object.processed_analysis['file_type']['full'].lower()
        return 'elf' in file_type

    def process_object(self, file_object):
        if self._is_supported_file_type(file_object):
            r2_command = 'docker run -v {}:/tmp/input input-vectors:latest /tmp/input 2>/dev/null'.format(file_object.file_path)
            output, return_code = execute_shell_command_get_return_code(r2_command)

            if return_code != 0:
                logging.error('[%s] Could not communicate with Bap plugin: %i (%s).',
                              self.NAME, return_code, output)
                file_object.processed_analysis[self.NAME] = {'summary': []}
            else:
                try:
                    file_object.processed_analysis[self.NAME] = json.loads(output)
                except json.JSONDecodeError:
                    logging.error("[%s] Could not decode JSON ouptut." % self.NAME)
                    logging.error(output)

            # TODO: add tags to file

        return file_object
