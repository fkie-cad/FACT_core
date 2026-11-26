from __future__ import annotations

import tarfile
from base64 import b64encode
from io import BytesIO
from pathlib import PurePosixPath

import pytest

from objects.file import FileObject
from objects.firmware import Firmware
from test.common_helper import create_test_firmware, generate_analysis_entry, get_test_data_dir
from test.integration.storage.helper import add_included_file
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
    buffer = BytesIO()
    packer.pack_included_files(uid, buffer)
    buffer.seek(0)
    with tarfile.open(fileobj=buffer, mode='r:gz') as tar:
        names = tar.getnames()

    assert sorted(names) == [
        'testfile1.zip',
        'testfile2',
    ]


def _pack_included_files_recursively(packer, uid):
    buffer = BytesIO()
    packer.pack_included_files_recursively(uid, buffer)
    buffer.seek(0)
    with tarfile.open(fileobj=buffer, mode='r:gz') as tar:
        names = tar.getnames()

    assert sorted(names) == [
        'testfile1.zip',
        'testfile1.zip_extracted/testfile1',
        'testfile2',
    ]


@pytest.fixture
def firmware(backend_db):
    fw = create_test_firmware()
    backend_db.insert_object(fw)
    return fw


@pytest.fixture
def store_file(backend_db, file_service, firmware):
    """
    Stores a File Object with `contents` at `path` in `parent` (default: the firmware) in the DB and the file storage,
    with a `file_type` result (`mime`) and the results in `analyses` (plugin → result)
    """

    def _store(contents: bytes, path: str, parent: FileObject | None = None, mime: str = 'text/plain', analyses=None):
        fo = FileObject.from_file(file_contents=contents, file_name=PurePosixPath(path).name)
        add_included_file(fo, parent or firmware, firmware, [path])
        for plugin, result in {'file_type': {'mime': mime, 'full': ''}, **(analyses or {})}.items():
            fo.processed_analysis[plugin] = generate_analysis_entry(analysis_result=result)
        backend_db.insert_object(fo)
        file_service.store_file(contents, fo.uid)
        return fo

    return _store


def _pack(packer: TarPacker, uid: str, recursive: bool = False) -> dict[str, tarfile.TarInfo]:
    buffer = BytesIO()
    if recursive:
        packer.pack_included_files_recursively(uid, buffer)
    else:
        packer.pack_included_files(uid, buffer)
    buffer.seek(0)
    with tarfile.open(fileobj=buffer, mode='r:gz') as tar:
        return {member.name: member for member in tar.getmembers()}


@pytest.fixture
def packer(common_db, file_service):
    return TarPacker(db=common_db, file_service=file_service)


@pytest.mark.parametrize('recursive', [False, True])
def test_symlink_target_with_spaces(packer, store_file, firmware, recursive):
    file_system = store_file(b'squashfs', '/rootfs.squashfs', mime='filesystem/squashfs')
    store_file(b'symbolic link -> /mnt/my data/config', '/etc/config', parent=file_system, mime='inode/symlink')

    members = _pack(packer, firmware.uid, recursive=True) if recursive else _pack(packer, file_system.uid)

    link = members['rootfs.squashfs_extracted/etc/config' if recursive else 'etc/config']
    assert link.issym()
    assert link.linkname == '/mnt/my data/config'


def _metadata(path: str, mode: str) -> dict:
    """An entry of the `file_system_metadata` result of a container for the file at `path` (with file type bits)"""
    return {'path': path, 'name': PurePosixPath(path).name, 'mode': mode, 'key': b64encode(path.encode()).decode()}


@pytest.mark.parametrize('recursive', [False, True])
def test_modes_from_file_system_metadata(packer, store_file, firmware, recursive):
    metadata = {'files': [_metadata('bin/busybox', '104755'), _metadata('etc/shadow', '100600')]}
    file_system = store_file(
        b'squashfs', '/rootfs.squashfs', mime='filesystem/squashfs', analyses={'file_system_metadata': metadata}
    )
    store_file(b'\x7fELF busybox', '/bin/busybox', parent=file_system, mime='application/x-executable')
    store_file(b'root:*:0:0', '/etc/shadow', parent=file_system)

    members = _pack(packer, firmware.uid, recursive=True) if recursive else _pack(packer, file_system.uid)

    prefix = 'rootfs.squashfs_extracted/' if recursive else ''
    assert members[f'{prefix}bin/busybox'].mode == 0o4755
    assert members[f'{prefix}etc/shadow'].mode == 0o600


@pytest.mark.parametrize('recursive', [False, True])
def test_executable_bit_without_file_system_metadata(packer, store_file, firmware, recursive):
    file_system = store_file(b'squashfs', '/rootfs.squashfs', mime='filesystem/squashfs')
    store_file(b'\x7fELF busybox', '/bin/busybox', parent=file_system, mime='application/x-executable')
    store_file(b'\x7fELF pie', '/bin/pie', parent=file_system, mime='application/x-pie-executable')
    store_file(b'\x7fELF libc', '/lib/libc.so.0', parent=file_system, mime='application/x-sharedlib')
    store_file(b'#!/bin/sh\necho', '/etc/init.d/rcS', parent=file_system, mime='text/x-shellscript')
    store_file(b'root::0:0', '/etc/passwd', parent=file_system)

    members = _pack(packer, firmware.uid, recursive=True) if recursive else _pack(packer, file_system.uid)

    prefix = 'rootfs.squashfs_extracted/' if recursive else ''
    modes = {name.removeprefix(prefix): member.mode for name, member in members.items() if name.startswith(prefix)}
    assert modes == {
        'bin/busybox': 0o755,
        'bin/pie': 0o755,
        'lib/libc.so.0': 0o755,
        'etc/init.d/rcS': 0o755,
        'etc/passwd': 0o644,
    }
