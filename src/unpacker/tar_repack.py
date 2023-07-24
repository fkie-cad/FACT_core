import logging
import os
import subprocess
from pathlib import Path
from subprocess import PIPE, STDOUT
from tempfile import TemporaryDirectory

from common_helper_files import get_binary_from_file

import config
from unpacker.unpack_base import UnpackBase


class TarRepack(UnpackBase):
    def tar_repack(self, file_path):
        extraction_directory = TemporaryDirectory(prefix='FACT_tar_repack', dir=config.backend.docker_mount_base_dir)
        self.extract_files_from_file(file_path, extraction_directory.name)

        archive_directory = TemporaryDirectory(prefix='FACT_tar_repack', dir=config.backend.temp_dir_path)
        archive_path = os.path.join(archive_directory.name, 'download.tar.gz')  # noqa: PTH118
        tar_binary = self._repack_extracted_files(Path(extraction_directory.name, 'files'), archive_path)

        extraction_directory.cleanup()
        archive_directory.cleanup()

        return tar_binary

    @staticmethod
    def _repack_extracted_files(extraction_dir: Path, out_file_path: str) -> bytes:
        tar_process = subprocess.run(
            f'tar -C {extraction_dir} -cvzf {out_file_path} .', shell=True, stdout=PIPE, stderr=STDOUT
        )
        logging.debug(f'tar -cvzf:\n {tar_process.stdout}')
        return get_binary_from_file(out_file_path)
