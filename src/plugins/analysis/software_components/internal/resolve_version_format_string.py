import json
import logging
import re
from contextlib import suppress
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import List

from docker.errors import DockerException
from docker.types import Mount

from helperFunctions.docker import run_docker_container

CONTAINER_TARGET_PATH = '/work'
DOCKER_IMAGE = 'fact/format_string_resolver'
DOCKER_OUTPUT_FILE = 'ghidra_output.json'
TIMEOUT = 300
KEY_FILE = 'key_file'


def extract_data_from_ghidra(input_file_data: bytes, key_strings: List[str], path: str) -> List[str]:
    with TemporaryDirectory(prefix='FSR_', dir=path) as tmp_dir:
        tmp_dir_path = Path(tmp_dir)
        ghidra_input_file = tmp_dir_path / 'ghidra_input'
        (tmp_dir_path / KEY_FILE).write_text(json.dumps(key_strings))
        ghidra_input_file.write_bytes(input_file_data)
        with suppress(DockerException, TimeoutError):
            run_docker_container(
                DOCKER_IMAGE,
                logging_label='FSR',
                timeout=TIMEOUT,
                command=f'/work/ghidra_input {CONTAINER_TARGET_PATH}',
                mounts=[
                    Mount(CONTAINER_TARGET_PATH, tmp_dir, type='bind'),
                ],
            )

        try:
            output_file = (tmp_dir_path / DOCKER_OUTPUT_FILE).read_text()
            return filter_implausible_results(json.loads(output_file))
        except (json.JSONDecodeError, FileNotFoundError):
            logging.debug('[FSR]: output file could not be read')
            return []


def filter_implausible_results(version_list: List[str]):
    return [version for version in version_list if re.search(r'\d\.\d', version)]
