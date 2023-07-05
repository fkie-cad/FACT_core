from __future__ import annotations

from objects.file import FileObject
from objects.firmware import Firmware
from test.common_helper import create_test_file_object, create_test_firmware

TEST_FO = create_test_file_object()
TEST_FO_2 = create_test_file_object(bin_path='get_files_test/testfile2')
TEST_FW = create_test_firmware()


def add_included_file(fo: FileObject, parent: FileObject, root_fw: Firmware, paths: list[str] | None = None):
    fo.parents.append(parent.uid)
    fo.parent_firmware_uids.add(root_fw.uid)
    parent.files_included.add(fo.uid)
    fo.virtual_file_path[parent.uid] = paths or ['/some/path']


def create_fw_with_child_fo():
    fo = create_test_file_object()
    fw = create_test_firmware()
    add_included_file(fo, fw, fw, [f'/folder/{fo.file_name}'])
    return fo, fw


def create_fw_with_parent_and_child():
    # fw -> parent_fo -> child_fo
    parent_fo, fw = create_fw_with_child_fo()
    child_fo = create_test_file_object()
    child_fo.uid = 'test_uid'
    add_included_file(child_fo, parent_fo, fw, [f'/folder/{child_fo.file_name}'])
    return fw, parent_fo, child_fo


def get_fo_with_2_root_fw():
    fw_1, parent_1, fo = create_fw_with_parent_and_child()
    fw_2 = create_test_firmware()
    fw_2.uid = 'fw2'
    add_included_file(fo, fw_2, fw_2)
    return fo, parent_1, fw_1, fw_2


def insert_test_fw(
    backend_db,
    uid,
    file_name='test.zip',
    device_class='class',
    vendor='vendor',
    device_name='name',
    version='1.0',
    release_date='1970-01-01',
    analysis: dict | None = None,
    tags: dict | None = None,
):  # pylint: disable=too-many-arguments
    test_fw = create_test_firmware(device_class=device_class, vendor=vendor, device_name=device_name, version=version)
    test_fw.uid = uid
    test_fw.file_name = file_name
    test_fw.release_date = release_date
    if analysis:
        test_fw.processed_analysis = analysis
    if tags:
        test_fw.tags = tags
    backend_db.insert_object(test_fw)
    return test_fw


def insert_test_fo(
    backend_db, uid, file_name='test.zip', size=1, analysis: dict | None = None, parent_fw=None, comments=None
):
    test_fo = create_test_file_object()
    test_fo.uid = uid
    test_fo.file_name = file_name
    test_fo.size = size
    test_fo.virtual_file_path = {}
    if analysis:
        test_fo.processed_analysis = analysis
    if parent_fw:
        test_fo.parent_firmware_uids = [parent_fw]
    if comments:
        test_fo.comments = comments
    backend_db.insert_object(test_fo)
