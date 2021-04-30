import logging
from contextlib import suppress
from typing import Optional, Tuple

import docker
from docker.errors import DockerException
from docker.types import Mount
from requests.exceptions import ReadTimeout


def run_docker_container(  # pylint: disable=too-many-arguments
    image: str, timeout: int = 300, command: Optional[str] = None, reraise: bool = False, privileged: bool = False,
    mount: Optional[Tuple[str, str]] = None, label: str = 'Docker', include_stderr: bool = True
) -> str:
    '''
    Run a docker container and get its output.

    :param image: the name of the docker image
    :param timeout: a timeout after which the execution is canceled
    :param command: the command to run in the container (optional)
    :param reraise: re-raise exceptions if they occur (timeout and docker exceptions)
    :param privileged: Run container with elevated privileges.
    :param mount: specifies a directory that gets mounted into the container;
                  structure: `(path_inside_container, source_path)`
    :param label: label used for logging output
    :param include_stderr: include stderr of the container in the output
    :return: the output of the docker container
    '''
    container = None
    try:
        kwargs = {'mounts': [Mount(*mount, read_only=False, type='bind')]} if mount else {}
        client = docker.from_env()
        container = client.containers.run(image, command=command, network_disabled=True, detach=True, privileged=privileged, **kwargs)
        container.wait(timeout=timeout)
        return container.logs(stderr=include_stderr).decode()
    except ReadTimeout:
        logging.warning('[{}]: timeout while processing'.format(label))
        if reraise:
            raise
    except (DockerException, IOError):
        logging.warning('[{}]: encountered process error while processing'.format(label))
        if reraise:
            raise
    finally:
        if container:
            with suppress(DockerException):
                container.stop()
            container.remove()
