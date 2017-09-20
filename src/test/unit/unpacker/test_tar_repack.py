import unittest
import os
import magic

from unpacker.tar_repack import tarRepack
from helperFunctions.fileSystem import get_test_data_dir


class Test_unpacker_tar_repack(unittest.TestCase):

    def setUp(self):
        self.repack_service = tarRepack()

    def test_tar_repack(self):
        file_path = os.path.join(get_test_data_dir(), 'container/test.zip')
        result = self.repack_service.tar_repack(file_path)
        file_type = magic.from_buffer(result, mime=True)
        self.assertTrue(file_type == 'application/x-gzip' or file_type == 'application/gzip', "Result is not an tar.gz file")


if __name__ == "__main__":
    unittest.main()
