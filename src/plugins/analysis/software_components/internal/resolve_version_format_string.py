from __future__ import annotations

import json
import logging
import re
from contextlib import suppress
from pathlib import Path
from tempfile import TemporaryDirectory

from docker.errors import DockerException
from docker.types import Mount

from helperFunctions.docker import run_docker_container

CONTAINER_TARGET_PATH = Path('/work')
INPUT_PATH = CONTAINER_TARGET_PATH / 'ghidra_input'
DOCKER_IMAGE = 'fact/format_string_resolver'
DOCKER_OUTPUT_FILE = 'ghidra_output.json'
TIMEOUT = 300
KEY_FILE = 'key_file'


def extract_data_from_ghidra(file_path: str, input_data: dict, path: str) -> list[str]:
    with TemporaryDirectory(prefix='FSR_', dir=path) as tmp_dir:
        tmp_dir_path = Path(tmp_dir)
        (tmp_dir_path / KEY_FILE).write_text(json.dumps(input_data))
        with suppress(DockerException, TimeoutError):
            proc = run_docker_container(
                DOCKER_IMAGE,
                logging_label='FSR',
                timeout=TIMEOUT,
                command=f'{INPUT_PATH} {CONTAINER_TARGET_PATH}',
                mounts=[
                    Mount(str(CONTAINER_TARGET_PATH), tmp_dir, type='bind'),
                    Mount(str(INPUT_PATH), file_path, type='bind', read_only=True),
                ],
            )
            if 'Traceback' in proc.stderr:
                logging.warning(f'error during FSR analysis: {proc.stderr}')

        try:
            output_file = (tmp_dir_path / DOCKER_OUTPUT_FILE).read_text()
            return filter_implausible_results(json.loads(output_file))
        except (json.JSONDecodeError, FileNotFoundError):
            logging.debug('[FSR]: output file could not be read')
            return []


def filter_implausible_results(version_list: list[str]):
    return [version for version in version_list if re.search(r'\d\.\d', version)]
