import os

import magic

from tests.common_helper import get_test_data_dir
from fact.unpacker.tar_repack import TarRepack


def test_tar_repack():
    repack_service = TarRepack()

    file_path = os.path.join(get_test_data_dir(), 'container/test.zip')  # noqa: PTH118
    result = repack_service.tar_repack(file_path)
    file_type = magic.from_buffer(result, mime=False)
    assert 'gzip compressed data' in file_type, 'Result is not an tar.gz file'
