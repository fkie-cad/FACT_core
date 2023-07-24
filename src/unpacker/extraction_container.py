from __future__ import annotations

import logging
from contextlib import suppress
from os import getgid, getuid
from pathlib import Path

import docker
import requests
from docker.errors import APIError, DockerException
from docker.types import Mount
from requests.adapters import HTTPAdapter, Retry

import config
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from docker.models.containers import Container
    from tempfile import TemporaryDirectory
    import multiprocessing

DOCKER_CLIENT = docker.from_env()
EXTRACTOR_DOCKER_IMAGE = 'fkiecad/fact_extractor'


class ExtractionContainer:
    def __init__(self, id_: int, tmp_dir: TemporaryDirectory, value: multiprocessing.managers.ValueProxy):
        self.id_ = id_
        self.tmp_dir = tmp_dir
        self.port = config.backend.unpacking.base_port + id_
        self.container_id = None
        self.exception = value
        self._adapter = HTTPAdapter(max_retries=Retry(total=5, backoff_factor=0.1))

    def start(self):
        if self.container_id is not None:
            raise RuntimeError('Already running.')

        try:
            self._start_container()
        except APIError as exception:
            if 'port is already allocated' in str(exception):
                self._recover_from_port_in_use(exception)

    def _start_container(self):
        volume = Mount('/tmp/extractor', self.tmp_dir.name, read_only=False, type='bind')
        container = DOCKER_CLIENT.containers.run(
            image=EXTRACTOR_DOCKER_IMAGE,
            ports={'5000/tcp': self.port},
            mem_limit=f'{config.backend.unpacking.memory_limit}m',
            mounts=[volume],
            volumes={'/dev': {'bind': '/dev', 'mode': 'rw'}},
            privileged=True,
            detach=True,
            remove=True,
            environment={'CHMOD_OWNER': f'{getuid()}:{getgid()}'},
            entrypoint='gunicorn --timeout 600 -w 1 -b 0.0.0.0:5000 server:app',
        )
        self.container_id = container.id
        logging.info(f'Started unpack worker {self.id_}')

    def stop(self):
        if self.container_id is None:
            raise RuntimeError('Container is not running.')

        logging.info(f'Stopping unpack worker {self.id_}')
        self._remove_container()

    def set_exception(self):
        return self.exception.set(1)

    def exception_occurred(self) -> bool:
        return self.exception.get() == 1

    def _remove_container(self, container: Container | None = None):
        if not container:
            container = self._get_container()
        container.stop(timeout=5)
        with suppress(DockerException):
            container.kill()
        with suppress(DockerException):
            container.remove()

    def _get_container(self) -> Container:
        return DOCKER_CLIENT.containers.get(self.container_id)

    def restart(self):
        self.stop()
        self.exception.set(0)
        self.container_id = None
        self.start()

    def _recover_from_port_in_use(self, exception: Exception):
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
        return any(tag == EXTRACTOR_DOCKER_IMAGE for tag in container.image.attrs['RepoTags'])

    def _has_same_port(self, container: Container) -> bool:
        return any(entry['HostPort'] == str(self.port) for entry in container.ports.get('5000/tcp', []))

    def get_logs(self) -> str:
        container = self._get_container()
        return container.logs().decode(errors='replace')

    def start_unpacking(self, tmp_dir: str, timeout: int | None = None):
        url = f'http://localhost:{self.port}/start/{Path(tmp_dir).name}'
        with requests.Session() as session:
            session.mount('http://', self._adapter)
            return session.get(url, timeout=timeout)
