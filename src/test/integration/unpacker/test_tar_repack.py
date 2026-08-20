from __future__ import annotations

import tarfile
from tempfile import TemporaryDirectory

import pytest

from objects.firmware import Firmware
from test.common_helper import get_test_data_dir
from unpacker.tar_repack import TarPacker


@pytest.mark.flaky(reruns=3)  # test may fail when the CI is very busy
@pytest.mark.SchedulerTestConfig(items_to_unpack=4)
def test_tar_repack(common_db, file_service, unpacking_scheduler, unpacking_finished_event):
    test_fw = Firmware.from_path(get_test_data_dir() / 'container/test_zip.7z')
    test_fw.release_date = '1990-01-16'
    test_fw.version, test_fw.vendor, test_fw.device_name, test_fw.device_class = ['foo'] * 4
    unpacking_scheduler.add_task(test_fw)
    assert unpacking_finished_event.wait(timeout=30)

    packer = TarPacker(db=common_db, file_service=file_service)
    _pack_included_files(packer, test_fw.uid)
    _pack_included_files_recursively(packer, test_fw.uid)


def _pack_included_files(packer, uid):
    with TemporaryDirectory() as tmp_dir:
        output_file = f'{tmp_dir}/download.tar.gz'
        packer.pack_included_files(uid, output_file)

        with tarfile.open(output_file, 'r:gz') as tar:
            names = tar.getnames()

    assert sorted(names) == [
        'testfile1.zip',
        'testfile2',
    ]


def _pack_included_files_recursively(packer, uid):
    with TemporaryDirectory() as tmp_dir:
        output_file = f'{tmp_dir}/download.tar.gz'
        packer.pack_included_files_recursively(uid, output_file)

        with tarfile.open(output_file, 'r:gz') as tar:
            names = tar.getnames()

    assert sorted(names) == [
        'testfile1.zip',
        'testfile1.zip_extracted/testfile1',
        'testfile2',
    ]
