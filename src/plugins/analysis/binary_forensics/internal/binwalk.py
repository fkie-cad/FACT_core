from __future__ import annotations

import json
import logging
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import TYPE_CHECKING

from docker.errors import DockerException
from docker.types import Mount
from pydantic import BaseModel
from requests.exceptions import JSONDecodeError, ReadTimeout

from analysis.plugin.plugin import AnalysisFailedError
from helperFunctions.docker import run_docker_container

if TYPE_CHECKING:
    from io import FileIO


DOCKER_IMAGE = 'refirmlabs/binwalk:latest'


class BinwalkSignatureResult(BaseModel):
    offset: int
    id: str
    size: int
    name: str
    confidence: int
    description: str


def get_binwalk_signature_analysis(file: FileIO, timeout: int) -> list[BinwalkSignatureResult]:
    return _parse_binwalk_output(_get_docker_output(file, timeout))


def _parse_binwalk_output(binwalk_output: list[dict]) -> list[BinwalkSignatureResult]:
    """
    Expected result structure: (binwalk 3.1.1)
    [
        {
            'Analysis': {
                'file_path': '/io/input',
                'file_map': [
                    {
                        'offset': <int>,
                        'id': <str>,
                        'size': <int>,
                        'name': <str>,
                        'confidence': <int>,
                        'description': <str>,
                        'always_display': <bool>,
                        'extraction_declined': <bool>,
                    },
                    ...
                ],
            }
        }
    ]
    The outer array has only one entry, since we analyze only one file
    """
    try:
        return [
            BinwalkSignatureResult(
                offset=file_result['offset'],
                id=file_result['id'],
                size=file_result['size'],
                name=file_result['name'],
                confidence=file_result['confidence'],
                description=file_result['description'],
            )
            for file_result in binwalk_output[0]['Analysis']['file_map']
        ]
    except (KeyError, IndexError) as err:
        # FixMe: sadly, there are no tags for the docker container versions, so we can't pin it at the moment
        # this should not happen -- if it happens, the plugin needs to be fixed
        logging.exception('Failed to binwalk result')
        raise AnalysisFailedError('Failed to binwalk result') from err


def _get_docker_output(file: FileIO, timeout: int) -> list[dict]:
    container_input_path = '/io/input'
    container_output_path = '/io/output'
    with NamedTemporaryFile() as temp_file:
        Path(temp_file.name).touch()
        try:
            run_docker_container(
                DOCKER_IMAGE,
                combine_stderr_stdout=True,
                timeout=timeout - 1,
                command=f'{container_input_path} -l {container_output_path}',
                mounts=[
                    Mount(container_input_path, file.name, type='bind', read_only=True),
                    Mount(container_output_path, temp_file.name, type='bind', read_only=False),
                ],
                logging_label='binwalk',
            )
            return json.loads(Path(temp_file.name).read_text())
        except ReadTimeout as err:
            raise AnalysisFailedError('Docker container timed out') from err
        except (DockerException, OSError) as err:
            raise AnalysisFailedError('Docker process error') from err
        except JSONDecodeError as err:
            raise AnalysisFailedError('Docker output JSON parsing error') from err
