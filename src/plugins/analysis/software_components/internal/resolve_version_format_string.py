import json
import logging
import re
from contextlib import suppress
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import List

import docker
from docker.errors import DockerException
from docker.types import Mount
from requests.exceptions import ReadTimeout

CONTAINER_TARGET_PATH = '/work'
DOCKER_IMAGE = 'fact/format_string_resolver'
DOCKER_OUTPUT_FILE = 'ghidra_output.json'
TIMEOUT = 300
KEY_FILE = 'key_file'


def extract_data_from_ghidra(input_file_data: bytes, key_strings: List[str]) -> List[str]:
    with TemporaryDirectory(prefix='FSR_') as tmp_dir:
        tmp_dir_path = Path(tmp_dir)
        ghidra_input_file = tmp_dir_path / 'ghidra_input'
        (tmp_dir_path / KEY_FILE).write_text(json.dumps(key_strings))
        ghidra_input_file.write_bytes(input_file_data)
        docker_output = run_docker_container(tmp_dir)
        logging.debug(docker_output)
        try:
            output_file = (tmp_dir_path / DOCKER_OUTPUT_FILE).read_bytes()
            return filter_implausible_results(json.loads(output_file))
        except (json.JSONDecodeError, FileNotFoundError):
            logging.debug("[FSR]: output file could not be read")
            return []


def filter_implausible_results(version_list: List[str]):
    return [version for version in version_list if re.search(r'\d\.\d', version)]


def run_docker_container(dir_path: str) -> str:
    container = None
    try:
        volume = Mount(CONTAINER_TARGET_PATH, dir_path, read_only=False, type='bind')
        client = docker.from_env()
        container = client.containers.run(DOCKER_IMAGE, mounts=[volume], network_disabled=True, detach=True)
        container.wait(timeout=TIMEOUT)
        return container.logs().decode()
    except ReadTimeout:
        logging.warning('[FSR]: timeout while processing')
    except (DockerException, IOError):
        logging.warning('[FSR]: encountered process error while processing')
    finally:
        if container:
            with suppress(DockerException):
                container.stop()
            container.remove()
