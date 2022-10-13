import logging
import shutil
from os import makedirs
from pathlib import Path
from time import sleep
from typing import List

import requests
from common_helper_files import safe_rglob

WORKER_TIMEOUT = 600


class UnpackBase:
    @staticmethod
    def get_extracted_files_dir(base_dir):
        return Path(base_dir, 'files')

    def extract_files_from_file(self, file_path: str, tmp_dir: str, worker_url: str) -> List[Path]:
        self._initialize_shared_folder(tmp_dir)
        try:
            shutil.copy2(file_path, str(Path(tmp_dir, 'input', Path(file_path).name)))
        except FileNotFoundError:
            # Waiting if file becomes available
            sleep(1)
            shutil.copy2(file_path, str(Path(tmp_dir, 'input', Path(file_path).name)))

        response = requests.get(worker_url, timeout=WORKER_TIMEOUT)
        if response.status_code == 200:
            return [item for item in safe_rglob(Path(tmp_dir, 'files')) if not item.is_dir()]
        logging.error(response.text, response.status_code)
        raise RuntimeError(f'Failed extraction of {file_path}')

    @staticmethod
    def _initialize_shared_folder(tmp_dir):
        for subpath in ['files', 'reports', 'input']:
            makedirs(str(Path(tmp_dir, subpath)), exist_ok=True)
