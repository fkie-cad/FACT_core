from __future__ import annotations

from test.common_helper import create_test_file_object, create_test_firmware

TEST_FO = create_test_file_object()
TEST_FO_2 = create_test_file_object(bin_path='get_files_test/testfile2')
TEST_FW = create_test_firmware()


def create_fw_with_child_fo():
    fo = create_test_file_object()
    fw = create_test_firmware()
    fo.parents.append(fw.uid)
    fo.parent_firmware_uids.add(fw.uid)
    fw.files_included.add(fo.uid)
    fw.virtual_file_path = {fw.uid: [f'|{fw.uid}|']}
    fo.virtual_file_path = {fw.uid: [f'|{fw.uid}|/folder/{fo.file_name}']}
    return fo, fw


def create_fw_with_parent_and_child():
    # fw -> parent_fo -> child_fo
    parent_fo, fw = create_fw_with_child_fo()
    child_fo = create_test_file_object()
    child_fo.uid = 'test_uid'
    parent_fo.files_included.add(child_fo.uid)
    child_fo.parents.append(parent_fo.uid)
    child_fo.parent_firmware_uids.add(fw.uid)
    child_fo.virtual_file_path = {fw.uid: [f'|{fw.uid}|{parent_fo.uid}|/folder/{child_fo.file_name}']}
    return fw, parent_fo, child_fo


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
    if analysis:
        test_fo.processed_analysis = analysis
    if parent_fw:
        test_fo.parent_firmware_uids = [parent_fw]
    if comments:
        test_fo.comments = comments
    backend_db.insert_object(test_fo)
