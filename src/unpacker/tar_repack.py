import logging
import os
from pathlib import Path
from tempfile import TemporaryDirectory

from common_helper_files import get_binary_from_file
from common_helper_process import execute_shell_command

from helperFunctions.config import get_temp_dir_path
from unpacker.unpack_base import UnpackBase


class TarRepack(UnpackBase):

    def tar_repack(self, file_path):
        extraction_directory = TemporaryDirectory(prefix='FACT_tar_repack', dir=get_temp_dir_path(self.config))
        self.extract_files_from_file(file_path, extraction_directory.name)

        archive_directory = TemporaryDirectory(prefix='FACT_tar_repack', dir=get_temp_dir_path(self.config))
        archive_path = os.path.join(archive_directory.name, 'download.tar.gz')
        tar_binary = self._repack_extracted_files(Path(extraction_directory.name, 'files'), archive_path)

        extraction_directory.cleanup()
        archive_directory.cleanup()

        return tar_binary

    @staticmethod
    def _repack_extracted_files(extraction_dir: Path, out_file_path: str) -> bytes:
        output = execute_shell_command('tar -C {} -cvzf {} .'.format(extraction_dir, out_file_path))
        logging.debug('tar -cvzf:\n {}'.format(output))
        return get_binary_from_file(out_file_path)
