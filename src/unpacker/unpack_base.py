import logging
import shutil
from os import getgid, getuid, makedirs
from pathlib import Path
from subprocess import PIPE, Popen

from common_helper_process import execute_shell_command_get_return_code


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

        output, return_code = execute_shell_command_get_return_code('docker run --privileged -v /dev:/dev -v {}:/tmp/extractor --rm fkiecad/fact_extractor'.format(tmp_dir))
        if return_code != 0:
            error = 'Failed to execute docker extractor with code {}:\n{}'.format(return_code, output)
            logging.error(error)
            raise RuntimeError(error)

        self.change_owner_back_to_me(tmp_dir)
        all_items = list(Path(tmp_dir, 'files').glob('**/*'))
        return [item for item in all_items if not item.is_dir()]

    def change_owner_back_to_me(self, directory: str = None, permissions='u+r'):
        with Popen('sudo chown -R {}:{} {}'.format(getuid(), getgid(), directory), shell=True, stdout=PIPE, stderr=PIPE) as pl:
            pl.communicate()
        self._grant_read_permission(directory, permissions)

    @staticmethod
    def _grant_read_permission(directory, permissions):
        with Popen('chmod --recursive {} {}'.format(permissions, directory), shell=True, stdout=PIPE, stderr=PIPE) as pl:
            pl.communicate()

    @staticmethod
    def _initialize_shared_folder(tmp_dir):
        for subpath in ['files', 'reports', 'input']:
            makedirs(str(Path(tmp_dir, subpath)), exist_ok=True)
