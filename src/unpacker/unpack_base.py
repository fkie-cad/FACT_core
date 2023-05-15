from __future__ import annotations

import logging
import shutil
from os import getgid, getuid, makedirs
from pathlib import Path
from subprocess import CalledProcessError

import requests
from common_helper_files import safe_rglob
from docker.types import Mount
from requests import ReadTimeout, exceptions

import config
from helperFunctions.docker import run_docker_container
from unpacker.extraction_container import EXTRACTOR_DOCKER_IMAGE, ExtractionContainer

WORKER_TIMEOUT = 600  # in seconds


class ExtractionError(Exception):
    pass


class UnpackBase:
    @staticmethod
    def get_extracted_files_dir(base_dir):
        return Path(base_dir, 'files')

    def extract_files_from_file(
        self, file_path: str, tmp_dir: str, container: ExtractionContainer | None = None
    ) -> list[Path]:
        self._initialize_shared_folder(tmp_dir)
        try:
            shutil.copy2(file_path, str(Path(tmp_dir, 'input', Path(file_path).name)))
        except FileNotFoundError:
            logging.exception(f'Error during extraction of {file_path}')
            raise

        if container:
            self._extract_with_worker(file_path, container, tmp_dir)
        else:  # start new container
            self._extract_with_new_container(tmp_dir)

        return [item for item in safe_rglob(Path(tmp_dir, 'files')) if not item.is_dir()]

    @staticmethod
    def _initialize_shared_folder(tmp_dir):
        for subpath in ['files', 'reports', 'input']:
            makedirs(str(Path(tmp_dir, subpath)), exist_ok=True)

    @staticmethod
    def _extract_with_worker(file_path: str, container: ExtractionContainer, tmp_dir: str):
        try:
            response = container.start_unpacking(tmp_dir, timeout=WORKER_TIMEOUT)
        except ReadTimeout as error:
            raise ExtractionError('Timeout during extraction.') from error
        except requests.exceptions.ConnectionError as error:
            raise ExtractionError('Extraction container could not be reached.') from error
        if response.status_code != 200:
            logging.error(response.text, response.status_code)
            raise ExtractionError(f'Extraction of {file_path} failed')

    @staticmethod
    def _extract_with_new_container(tmp_dir: str):
        try:
            result = run_docker_container(
                EXTRACTOR_DOCKER_IMAGE,
                combine_stderr_stdout=True,
                privileged=True,
                mem_limit=f'{config.backend.unpacking.memory_limit}m',
                mounts=[
                    Mount('/dev/', '/dev/', type='bind'),
                    Mount('/tmp/extractor', tmp_dir, type='bind'),
                ],
                command=f'--chown {getuid()}:{getgid()}',
            )
        except exceptions.RequestException as err:
            logging.warning(f'Request exception executing docker extractor:\n{err}')
            return

        try:
            result.check_returncode()
        except CalledProcessError as err:
            error = f'Failed to execute docker extractor with code {err.returncode}:\n{err.stdout}'
            logging.error(error)
            raise RuntimeError(error) from err
