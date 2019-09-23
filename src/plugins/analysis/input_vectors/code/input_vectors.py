import json
import logging
from subprocess import DEVNULL, PIPE, Popen

from analysis.PluginBase import AnalysisBasePlugin

DOCKER_IMAGE = 'input-vectors:latest'
TIMEOUT = 2 # in minutes

class AnalysisPlugin(AnalysisBasePlugin):
    '''
    This plugin determines possible input vectors of Linux ELF executables.
    Examples are:
    - network
    - stdin
    - kernel via syscalls
    '''
    NAME = 'input_vectors'
    DESCRIPTION = 'Determines possible input vectors of an ELF executable like stdin, network, or syscalls.'
    DEPENDENCIES = ['file_type']
    VERSION = '0.1'

    def __init__(self, plugin_adminstrator, config=None, recursive=True):
        self.config = config
        super().__init__(plugin_adminstrator, config=config, recursive=recursive, plugin_path=__file__)
        logging.info('Up and running.')

    @staticmethod
    def _is_supported_file_type(file_object):
        file_type = file_object.processed_analysis['file_type']['full'].lower()
        return 'elf' in file_type

    def process_object(self, file_object):
        if self._is_supported_file_type(file_object):
            r2_command = 'timeout --signal=SIGKILL {}m docker run -v {}:/tmp/input {} /tmp/input'.format(
                TIMEOUT, file_object.file_path, DOCKER_IMAGE)
            pl = Popen(r2_command, shell=True, stdout=PIPE, stderr=DEVNULL)
            output = pl.communicate()[0].decode('utf-8', errors='replace')
            return_code = pl.returncode
            if return_code in [0, 124, 128 + 9]:
                try:
                    file_object.processed_analysis[self.NAME] = json.loads(output)
                except json.JSONDecodeError:
                    logging.error('Could not decode JSON ouptut.')
                    logging.error(output)
                if return_code in [124, 128 + 9]:
                    logging.warning('input_vectors timed out on {}. Analysis might not be complete.'.format(file_object.get_uid()))
                    file_object.processed_analysis[self.NAME]['warning'] = 'Analysis timed out. It might not be complete.'
            else:
                logging.error('Could not communicate with radare2 plugin: {} ({})\nUID: {}'.format(return_code, output, file_object.get_uid()))
                file_object.processed_analysis[self.NAME] = {'summary': []}

        return file_object
