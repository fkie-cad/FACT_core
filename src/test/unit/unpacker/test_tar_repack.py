import gc
import os
import unittest
from pathlib import Path

import magic

from test.common_helper import get_config_for_testing, get_test_data_dir
from unpacker.tar_repack import TarRepack


class TestTarRepack(unittest.TestCase):

    def setUp(self):
        self.config = get_config_for_testing()
        self.docker_mount_base_dir = Path('/tmp/fact-docker-mount-base-dir')
        self.docker_mount_base_dir.mkdir(0o770, exist_ok=True)
        self.config.set('data_storage', 'docker-mount-base-dir', str(self.docker_mount_base_dir))
        self.repack_service = TarRepack(config=self.config)

    def tearDown(self):
        gc.collect()

    def test_tar_repack(self):
        file_path = os.path.join(get_test_data_dir(), 'container/test.zip')
        result = self.repack_service.tar_repack(file_path)
        file_type = magic.from_buffer(result, mime=False)
        assert 'gzip compressed data' in file_type, 'Result is not an tar.gz file'
