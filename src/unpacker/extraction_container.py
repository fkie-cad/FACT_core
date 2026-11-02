from __future__ import annotations

import logging
from contextlib import suppress
from http import HTTPStatus
from os import getgid, getuid
from pathlib import Path
from typing import TYPE_CHECKING

import docker
import requests
from docker.errors import APIError, DockerException
from docker.types import Mount
from requests.adapters import HTTPAdapter, Retry

import config

if TYPE_CHECKING:
    import multiprocessing
    from tempfile import TemporaryDirectory

    from docker.models.containers import Container
    from requests.adapters import Response

DOCKER_CLIENT = docker.from_env()
# the firmware storage directory is mounted read-only at this path inside the container, so that files can be unpacked
# without copying them to the shared folder first
CONTAINER_FW_STORAGE_DIR = '/fact_fw_data'
REQUIRED_EXTRACTOR_FEATURES = {'input_path'}


class ExtractorOutdatedError(RuntimeError):
    pass


class ExtractionContainer:
    def __init__(self, id_: int, tmp_dir: TemporaryDirectory, value: multiprocessing.managers.ValueProxy):
        self.id_ = id_
        self.tmp_dir = tmp_dir
        self.port = config.backend.unpacking.base_port + id_
        self.container_id = None
        self.container_pid = 0
        self.exception = value
        self._adapter = HTTPAdapter(max_retries=Retry(total=3, backoff_factor=0.1))

    def start(self) -> None:
        if self.container_id is not None:
            raise RuntimeError('Already running.')

        try:
            self._start_container()
        except APIError as exception:
            if 'port is already allocated' in str(exception):
                self._recover_from_port_in_use(exception)

    def _start_container(self) -> None:
        volume = Mount('/tmp/extractor', self.tmp_dir.name, read_only=False, type='bind')  # noqa: S108
        storage_dir = Path(config.backend.firmware_file_storage_directory).resolve()
        storage_dir.mkdir(parents=True, exist_ok=True)
        fw_storage = Mount(CONTAINER_FW_STORAGE_DIR, str(storage_dir), read_only=True, type='bind')
        container = DOCKER_CLIENT.containers.run(
            image=config.backend.unpacking.docker_image,
            ports={'5000/tcp': self.port},
            mem_limit=f'{config.backend.unpacking.memory_limit}m',
            mounts=[volume, fw_storage],
            volumes={'/dev': {'bind': '/dev', 'mode': 'rw'}},
            privileged=True,
            detach=True,
            remove=True,
            environment={'CHMOD_OWNER': f'{getuid()}:{getgid()}'},
            entrypoint='gunicorn --timeout 600 -w 1 -b 0.0.0.0:5000 server:app',
        )
        self.container_id = container.id
        logging.info(f'Started unpack worker {self.id_}')
        container.reload()
        self.container_pid = container.attrs['State'].get('Pid', 0)

    def stop(self) -> None:
        if self.container_id is None:
            raise RuntimeError('Container is not running.')

        logging.info(f'Stopping unpack worker {self.id_}')
        self._remove_container()

    def set_exception(self):  # noqa: ANN201
        return self.exception.set(1)

    def exception_occurred(self) -> bool:
        return self.exception.get() == 1

    def _remove_container(self, container: Container | None = None) -> None:
        if not container:
            container = self._get_container()
        container.stop(timeout=5)
        with suppress(DockerException):
            container.kill()
        with suppress(DockerException):
            container.remove()

    def _get_container(self) -> Container:
        return DOCKER_CLIENT.containers.get(self.container_id)

    def restart(self) -> None:
        self.stop()
        self.exception.set(0)
        self.container_id = None
        self.start()

    def _recover_from_port_in_use(self, exception: Exception) -> None:
        logging.warning('Extractor port already in use -> trying to remove old container...')
        for running_container in DOCKER_CLIENT.containers.list():
            if self._is_extractor_container(running_container) and self._has_same_port(running_container):
                self._remove_container(running_container)
                self._start_container()
                return
        logging.error('Could not free extractor port')
        raise RuntimeError('Could not create extractor container') from exception

    @staticmethod
    def _is_extractor_container(container: Container) -> bool:
        extractor_tag = config.backend.unpacking.docker_image
        if ':' not in extractor_tag:
            extractor_tag = f'{extractor_tag}:latest'
        return any(tag == extractor_tag for tag in container.image.attrs['RepoTags'])

    def _has_same_port(self, container: Container) -> bool:
        return any(entry['HostPort'] == str(self.port) for entry in container.ports.get('5000/tcp', []))

    def get_logs(self) -> str:
        container = self._get_container()
        return container.logs().decode(errors='replace')

    def start_unpacking(self, tmp_dir: str, input_path: str | None = None, timeout: int | None = None) -> Response:
        """
        Start the extraction in the container. If `input_path` (the path of the input file relative to the firmware
        storage directory) is set, the container reads the file directly from the storage. Otherwise, the file is
        expected to be in the "input" folder inside `tmp_dir`.
        """
        response = self._check_connection()
        if response.status_code != HTTPStatus.OK:
            return response
        url = f'http://localhost:{self.port}/start/{Path(tmp_dir).name}'
        params = {'input': input_path} if input_path else None
        return requests.get(url, params=params, timeout=timeout)

    def check_compatibility(self) -> None:
        """
        Make sure that the extractor image supports all features that are required by FACT (older versions of the
        extractor do not return a list of features in the /status response).
        """
        # the container may have just been started -> wait longer for it to become ready
        response = self._check_connection(retries=Retry(total=8, backoff_factor=0.2))
        try:
            features = set(response.json().get('features', []))
        except (ValueError, AttributeError):
            features = set()
        if missing := REQUIRED_EXTRACTOR_FEATURES - features:
            image = config.backend.unpacking.docker_image
            raise ExtractorOutdatedError(
                f'The extractor docker image "{image}" is outdated (missing features: {", ".join(sorted(missing))}). '
                f'Please update it (e.g. with "docker pull {image}").'
            )

    def _check_connection(self, retries: Retry | None = None) -> Response:
        """
        Try to access the /status endpoint of the container to make sure the container is ready.
        The `self._adapter` includes a retry in order to wait if the connection cannot be established directly.
        We can't retry on the actual /start endpoint (or else we would start unpacking multiple times).
        """
        url = f'http://localhost:{self.port}/status'
        with requests.Session() as session:
            session.mount('http://', HTTPAdapter(max_retries=retries) if retries else self._adapter)
            return session.get(url, timeout=5)
