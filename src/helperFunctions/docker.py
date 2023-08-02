from __future__ import annotations

import logging
from contextlib import suppress
from subprocess import CompletedProcess

import docker
from docker.errors import APIError, DockerException, ImageNotFound
from requests.exceptions import ReadTimeout


def run_docker_container(
    image: str, logging_label: str = 'Docker', timeout: int = 300, combine_stderr_stdout: bool = False, **kwargs
) -> CompletedProcess:
    """
    This is a convinience function that runs a docker container and returns a
    subprocess.CompletedProcess instance for the command ran in the container.
    All remaining keyword args are passed to `docker.containers.run`.

    :param image: The name of the docker image
    :param logging_label: Label used for logging
    :param timeout: Timeout after which the execution is canceled
    :param combine_stderr_stdout: Whether to combine stderr and stdout or not

    :return: A subprocess.CompletedProcess instance for the command ran in the
        container.

    :raises docker.errors.ImageNotFound: If the docker image was not found
    :raises requests.exceptions.ReadTimeout: If the timeout was reached
    :raises docker.errors.APIError: If the communication with docker fails
    """
    # TODO verify that bind mounts in kwargs["mounts"] only contain files in docker-mount-base-dir
    # If they don't just copy them to docker-mount-base-dir and change the mounts

    client = docker.client.from_env()
    kwargs.setdefault('detach', True)

    try:
        container = client.containers.run(image, **kwargs)
    except (ImageNotFound, APIError):
        logging.warning(f'[{logging_label}]: encountered docker error while processing')
        raise

    try:
        response = container.wait(timeout=timeout)
        exit_code = response['StatusCode']
        stdout = (
            container.logs(stdout=True, stderr=False).decode()
            if not combine_stderr_stdout
            else container.logs(stdout=True, stderr=True).decode()
        )
        stderr = container.logs(stdout=False, stderr=True).decode() if not combine_stderr_stdout else None
    except ReadTimeout:
        logging.warning(f'[{logging_label}]: timeout while processing')
        raise
    except APIError:
        logging.warning(f'[{logging_label}]: encountered docker error while processing')
        raise
    finally:
        with suppress(DockerException):
            container.stop()
            container.remove()

    # We do not know the docker entrypoint so we just insert a generic "entrypoint"
    command = kwargs.get('command', None)
    if isinstance(command, str):
        args: str | list[str] = 'entrypoint' + command
    elif isinstance(command, list):
        args = ['entrypoint', *command]
    else:
        args = ['entrypoint']

    return CompletedProcess(args=args, returncode=exit_code, stdout=stdout, stderr=stderr)
