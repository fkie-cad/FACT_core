import logging
from json import JSONDecodeError, loads

from docker.errors import DockerException
from docker.types import Mount
from requests.exceptions import ReadTimeout

from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.docker import run_docker_container
from objects.file import FileObject

DOCKER_IMAGE = 'input-vectors:latest'
TIMEOUT_IN_SECONDS = 120
CONTAINER_TARGET_PATH = '/tmp/input'


class AnalysisPlugin(AnalysisBasePlugin):
    """
    This plugin determines possible input vectors of Linux ELF executables.
    Examples are:
    - network
    - stdin
    - kernel via syscalls
    """

    NAME = 'input_vectors'
    DESCRIPTION = 'Determines possible input vectors of an ELF executable like stdin, network, or syscalls.'
    DEPENDENCIES = ['file_type']  # noqa: RUF012
    VERSION = '0.1.3'
    MIME_WHITELIST = ['application/x-executable', 'application/x-object', 'application/x-sharedlib']  # noqa: RUF012
    FILE = __file__

    def process_object(self, file_object: FileObject):
        try:
            result = run_docker_container(
                DOCKER_IMAGE,
                # We explicitly don't want stderr to ignore "Cannot analyse at [...]"
                combine_stderr_stdout=False,
                logging_label=self.NAME,
                timeout=TIMEOUT_IN_SECONDS,
                command=CONTAINER_TARGET_PATH,
                mounts=[
                    Mount(CONTAINER_TARGET_PATH, file_object.file_path, type='bind', read_only=True),
                ],
            )
            file_object.processed_analysis[self.NAME] = loads(result.stdout)
        except ReadTimeout:
            file_object.processed_analysis[self.NAME]['failed'] = 'Analysis timed out. It might not be complete.'
        except (DockerException, OSError):
            file_object.processed_analysis[self.NAME]['failed'] = 'Analysis issues. It might not be complete.'
        except JSONDecodeError:
            logging.error('[input_vectors]: Could not decode JSON output:', exc_info=True)

        return file_object
