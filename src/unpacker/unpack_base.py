import logging
import shutil
from os import getgid, getuid, makedirs
from pathlib import Path

from common_helper_files import safe_rglob
from docker.types import Mount

from helperFunctions.docker import run_docker_container


class UnpackBase:
    def __init__(self, config=None, worker_id=None):
        self.config = config
        self.worker_id = worker_id

    @staticmethod
    def get_extracted_files_dir(base_dir):
        return Path(base_dir, 'files')

    def extract_files_from_file(self, file_path, tmp_dir):
        self._initialize_shared_folder(tmp_dir)
        shutil.copy2(file_path, str(Path(tmp_dir, 'input', Path(file_path).name)))

        output, exit_code = run_docker_container(
            'fkiecad/fact_extractor',
            privileged=True,
            mem_limit=f"{self.config.get('unpack', 'memory_limit', fallback='1024')}m",
            mounts=[
                Mount('/dev/', '/dev/', type='bind'),
                Mount('/tmp/extractor', tmp_dir, type='bind'),
            ],
            command=f'--chown {getuid()}:{getgid()}'
        )

        if exit_code != 0:
            error = f'Failed to execute docker extractor with code {exit_code}:\n{output}'
            logging.error(error)
            raise RuntimeError(error)

        return [item for item in safe_rglob(Path(tmp_dir, 'files')) if not item.is_dir()]

    @staticmethod
    def _initialize_shared_folder(tmp_dir):
        for subpath in ['files', 'reports', 'input']:
            makedirs(str(Path(tmp_dir, subpath)), exist_ok=True)
