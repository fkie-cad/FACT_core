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

    def extract_files_from_file(self, file_path, tmp_dir):
        self._initialize_shared_folder(tmp_dir)
        shutil.copy2(file_path, Path(tmp_dir.name, 'input', Path(file_path).name))

        output, return_code = execute_shell_command_get_return_code('docker run -v {}:/tmp/extractor --rm fact_extractor'.format(tmp_dir.name))
        if return_code != 0:
            error = 'Failed to execute docker extractor with code {}:\n{}'.format(return_code, output)
            logging.error(error)
            raise RuntimeError(error)

        all_items = list(Path(tmp_dir.name, 'files').glob('**/*'))
        return [item for item in all_items if not item.is_dir()]

    def change_owner_back_to_me(self, directory=None, permissions='u+r'):
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
            makedirs(str(Path(tmp_dir.name, subpath)), exist_ok=True)
