import logging
from contextlib import suppress

import docker
from docker.errors import APIError, DockerException, ImageNotFound

client = docker.client.from_env()


def run_docker_container(image: str, logging_label: str = 'Docker', timeout: int = 300,  stderr=True, **kwargs):
    """
    This is a convinience function that runs a docker container and returns the output and exit code of the command.
    All remaining keyword args are passed to `docker.containers.run`.

    :param image: The name of the docker image
    :param logging_label: Label used for logging
    :param timeout: Timeout after which the execution is canceled
    :param stderr: Whether to include stderr or not in the output

    :return: Output and exit code as tuple

    :raises ImageNotFound: If the docker image was not found
    :raises TimeoutError: If the timeout was reached
    :raises APIError: If the communication with docker fails
    """
    kwargs.setdefault('detach', True)

    try:
        container = client.containers.run(image, **kwargs)
    except (ImageNotFound, APIError):
        logging.warning(f'[{logging_label}]: encountered process error while processing')
        raise

    try:
        response = container.wait(timeout=timeout)
        exit_code = response['StatusCode']
    except TimeoutError:
        logging.warning(f'[{logging_label}]: timeout while processing')
        with suppress(DockerException):
            container.stop()
            container.remove()

        raise

    try:
        output = container.logs(stderr=stderr).decode()
    except APIError:
        logging.warning(f'[{logging_label}]: encountered docker error while processing')
        raise
    finally:
        with suppress(DockerException):
            container.stop()
            container.remove()

    return output, exit_code
