import logging
from contextlib import suppress
from typing import Optional, Tuple

import docker
from docker.errors import DockerException
from docker.types import Mount
from requests.exceptions import ReadTimeout


def run_docker_container(image: str, timeout: int = 300, command: Optional[str] = None, reraise: bool = False,
                         mount: Optional[Tuple[str, str]] = None, label: str = 'Docker', include_stderr: bool = True) -> str:
    container = None
    try:
        kwargs = {'mounts': [Mount(*mount, read_only=False, type='bind')]} if mount else {}
        client = docker.from_env()
        container = client.containers.run(image, command=command, network_disabled=True, detach=True, **kwargs)
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
