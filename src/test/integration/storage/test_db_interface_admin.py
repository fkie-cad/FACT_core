from ...common_helper import create_test_firmware
from .helper import TEST_FW, create_fw_with_child_fo, create_fw_with_parent_and_child


def test_delete_fo(real_database):
    assert real_database.common.exists(TEST_FW.uid) is False
    real_database.backend.insert_object(TEST_FW)
    assert real_database.common.exists(TEST_FW.uid) is True
    real_database.admin.delete_object(TEST_FW.uid)
    assert real_database.common.exists(TEST_FW.uid) is False


def test_delete_cascade(real_database):
    fo, fw = create_fw_with_child_fo()
    assert real_database.common.exists(fo.uid) is False
    assert real_database.common.exists(fw.uid) is False
    real_database.backend.insert_object(fw)
    real_database.backend.insert_object(fo)
    assert real_database.common.exists(fo.uid) is True
    assert real_database.common.exists(fw.uid) is True
    real_database.admin.delete_object(fw.uid)
    assert real_database.common.exists(fw.uid) is False
    assert real_database.common.exists(fo.uid) is False, 'deletion should be cascaded to child objects'


def test_remove_vp_no_other_fw(real_database):
    fo, fw = create_fw_with_child_fo()
    real_database.backend.insert_object(fw)
    real_database.backend.insert_object(fo)

    with real_database.admin.get_read_write_session() as session:
        removed_vps, deleted_uids = real_database.admin._remove_virtual_path_entries(fw.uid, fo.uid, session)  # pylint: disable=protected-access

    assert removed_vps == 0
    assert deleted_uids == {fo.uid}


def test_remove_vp_other_fw(real_database):
    fo, fw = create_fw_with_child_fo()
    fo.virtual_file_path.update({'some_other_fw_uid': ['some_vfp']})
    real_database.backend.insert_object(fw)
    real_database.backend.insert_object(fo)

    with real_database.admin.get_read_write_session() as session:
        removed_vps, deleted_files = real_database.admin._remove_virtual_path_entries(fw.uid, fo.uid, session)  # pylint: disable=protected-access
    fo_entry = real_database.common.get_object(fo.uid)

    assert fo_entry is not None
    assert removed_vps == 1
    assert deleted_files == set()
    assert fw.uid not in fo_entry.virtual_file_path


def test_delete_firmware(real_database):
    fw, parent, child = create_fw_with_parent_and_child()
    real_database.backend.insert_object(fw)
    real_database.backend.insert_object(parent)
    real_database.backend.insert_object(child)

    removed_vps, deleted_files = real_database.admin.delete_firmware(fw.uid)

    assert removed_vps == 0
    assert deleted_files == 3
    assert child.uid in real_database.admin.intercom.deleted_files
    assert parent.uid in real_database.admin.intercom.deleted_files
    assert fw.uid in real_database.admin.intercom.deleted_files
    assert real_database.common.exists(fw.uid) is False
    assert real_database.common.exists(parent.uid) is False, 'should have been deleted by cascade'
    assert real_database.common.exists(child.uid) is False, 'should have been deleted by cascade'


def test_delete_but_fo_is_in_fw(real_database):
    fo, fw = create_fw_with_child_fo()
    fw2 = create_test_firmware()
    fw2.uid = 'fw2_uid'
    fo.parents.append(fw2.uid)
    fo.virtual_file_path.update({fw2.uid: [f'|{fw2.uid}|/some/path']})
    real_database.backend.insert_object(fw)
    real_database.backend.insert_object(fw2)
    real_database.backend.insert_object(fo)

    removed_vps, deleted_files = real_database.admin.delete_firmware(fw.uid)

    assert removed_vps == 1
    assert deleted_files == 1
    assert fo.uid not in real_database.admin.intercom.deleted_files
    fo_entry = real_database.common.get_object(fo.uid)
    assert fw.uid not in fo_entry.virtual_file_path
    assert fw2.uid in fo_entry.virtual_file_path
    assert fw.uid in real_database.admin.intercom.deleted_files
    assert real_database.common.exists(fw.uid) is False
    assert real_database.common.exists(fo.uid) is True, 'should have been spared by cascade delete because it is in another FW'
