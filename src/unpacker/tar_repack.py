from common_helper_files import get_binary_from_file
import logging
import os
from subprocess import Popen, PIPE
from tempfile import TemporaryDirectory

from unpacker.unpackBase import UnpackBase


class tarRepack(UnpackBase):

    def tar_repack(self, file_path):
        extraction_dir = TemporaryDirectory(prefix="FAF_tar_repack")
        container_storage = TemporaryDirectory(prefix="FAF_tar_repack")
        self.extract_files_from_file(file_path, extraction_dir.name)
        out_file_path = os.path.join(container_storage.name, "download.tar.gz")
        output = Popen('tar -C {} -cvzf {} .'.format(extraction_dir.name, out_file_path), shell=True, stdout=PIPE).stdout.read().decode()
        logging.debug("tar -cvzf:\n {}".format(output))
        tar = get_binary_from_file(out_file_path)
        extraction_dir.cleanup()
        container_storage.cleanup()
        return tar
