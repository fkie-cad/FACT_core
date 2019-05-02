import logging
import shutil
from os import getgid, getuid, makedirs
from pathlib import Path

from common_helper_files import safe_rglob
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

        output, return_code = execute_shell_command_get_return_code(
            'docker run --privileged -m {}m -v /dev:/dev -v {}:/tmp/extractor --rm fkiecad/fact_extractor'.format(self.config.get('unpack', 'memory_limit', fallback='1024'), tmp_dir)
        )
        if return_code != 0:
            error = 'Failed to execute docker extractor with code {}:\n{}'.format(return_code, output)
            logging.error(error)
            raise RuntimeError(error)

        self.change_owner_back_to_me(tmp_dir)
        return [item for item in safe_rglob(Path(tmp_dir, 'files')) if not item.is_dir()]

    def change_owner_back_to_me(self, directory: str = None, permissions='u+r'):
        execute_shell_command_get_return_code('sudo chown -R {}:{} {}'.format(getuid(), getgid(), directory))
        self._grant_read_permission(directory, permissions)

    @staticmethod
    def _grant_read_permission(directory, permissions):
        execute_shell_command_get_return_code('chmod --recursive {} {}'.format(permissions, directory))

    @staticmethod
    def _initialize_shared_folder(tmp_dir):
        for subpath in ['files', 'reports', 'input']:
            makedirs(str(Path(tmp_dir, subpath)), exist_ok=True)
