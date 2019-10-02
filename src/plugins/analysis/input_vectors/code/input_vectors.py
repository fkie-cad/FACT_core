import logging
from contextlib import suppress
from json import JSONDecodeError, loads

import docker
from docker.errors import APIError, DockerException, ImageNotFound
from docker.types import Mount
from requests.exceptions import ConnectionError as RequestConnectionError, ReadTimeout

from analysis.PluginBase import AnalysisBasePlugin

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
    VERSION = '0.1'
    MIME_WHITELIST = ['application/x-executable', 'application/x-object', 'application/x-sharedlib']

    def __init__(self, plugin_administrator, config=None, recursive=True):
        self.config = config
        super().__init__(plugin_administrator, config=config, recursive=recursive, plugin_path=__file__)
        logging.info('Up and running.')

    def process_object(self, file_object):
        container = None
        volume = Mount(CONTAINER_TARGET_PATH, file_object.file_path, read_only=True, type='bind')
        try:
            client = docker.from_env()
            container = client.containers.run(
                DOCKER_IMAGE, CONTAINER_TARGET_PATH, network_disabled=True, mounts=[volume], detach=True
            )
            container.wait(timeout=TIMEOUT_IN_SECONDS)
            file_object.processed_analysis[self.NAME] = loads(container.logs(stderr=False).decode())
        except (ImageNotFound, APIError, DockerException, RequestConnectionError):
            file_object.processed_analysis[self.NAME]['warning'] = 'Analysis issues. It might not be complete.'
        except ReadTimeout:
            file_object.processed_analysis[self.NAME]['warning'] = 'Analysis timed out. It might not be complete.'
        except JSONDecodeError:
            logging.error('Could not decode JSON output.')
            logging.error(container.logs().decode())
        finally:
            if container:
                with suppress(APIError):
                    container.stop()
                container.remove()

        return file_object
