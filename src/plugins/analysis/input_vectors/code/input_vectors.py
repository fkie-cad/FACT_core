import logging
from json import JSONDecodeError, loads
from pathlib import Path
from tempfile import TemporaryDirectory

from docker.errors import DockerException
from requests.exceptions import ReadTimeout

from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.docker import run_docker_container
from objects.file import FileObject

DOCKER_IMAGE = 'input-vectors:latest'
TIMEOUT_IN_SECONDS = 120
CONTAINER_TARGET_PATH = '/tmp/input'


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
    VERSION = '0.1.1'
    MIME_WHITELIST = ['application/x-executable', 'application/x-object', 'application/x-sharedlib']

    def __init__(self, plugin_administrator, config=None, recursive=True):
        self.config = config
        super().__init__(plugin_administrator, config=config, recursive=recursive, plugin_path=__file__)
        logging.info('Up and running.')

    def process_object(self, file_object: FileObject):
        with TemporaryDirectory(prefix=self.NAME) as tmp_dir:
            file_path = Path(tmp_dir) / file_object.file_name
            file_path.write_bytes(file_object.binary)
            try:
                result = run_docker_container(
                    DOCKER_IMAGE, TIMEOUT_IN_SECONDS, CONTAINER_TARGET_PATH, reraise=True,
                    mount=(CONTAINER_TARGET_PATH, str(file_path)), label=self.NAME, include_stderr=False
                )
                file_object.processed_analysis[self.NAME] = loads(result)
            except ReadTimeout:
                file_object.processed_analysis[self.NAME]['warning'] = 'Analysis timed out. It might not be complete.'
            except (DockerException, IOError):
                file_object.processed_analysis[self.NAME]['warning'] = 'Analysis issues. It might not be complete.'
            except JSONDecodeError:
                logging.error('Could not decode JSON output: {}'.format(repr(result)))

            return file_object
