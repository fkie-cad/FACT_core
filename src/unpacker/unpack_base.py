import logging
import shutil
import subprocess
from os import getgid, getuid, makedirs
from pathlib import Path
from subprocess import PIPE, STDOUT

from common_helper_files import safe_rglob


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

        docker_p = subprocess.run(
            'docker run --privileged -m {}m -v /dev:/dev -v {}:/tmp/extractor --rm fkiecad/fact_extractor --chown {}:{}'.format(
                self.config.get('unpack', 'memory_limit', fallback='1024'), tmp_dir, getuid(), getgid()
            ),
            shell=True,
            stdout=PIPE,
            stderr=STDOUT,
            text=True,
        )
        if docker_p.returncode != 0:
            error = 'Failed to execute docker extractor with code {}:\n{}'.format(docker_p.returncode, docker_p.stdout)
            logging.error(error)
            raise RuntimeError(error)

        return [item for item in safe_rglob(Path(tmp_dir, 'files')) if not item.is_dir()]

    @staticmethod
    def _initialize_shared_folder(tmp_dir):
        for subpath in ['files', 'reports', 'input']:
            makedirs(str(Path(tmp_dir, subpath)), exist_ok=True)
