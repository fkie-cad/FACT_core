from ...common_helper import create_test_firmware
from .helper import TEST_FW, create_fw_with_child_fo, create_fw_with_parent_and_child


def test_delete_fo(admin_db, common_db, backend_db):
    assert common_db.exists(TEST_FW.uid) is False
    backend_db.insert_object(TEST_FW)
    assert common_db.exists(TEST_FW.uid) is True
    admin_db.delete_object(TEST_FW.uid)
    assert common_db.exists(TEST_FW.uid) is False


def test_delete_cascade(admin_db, common_db, backend_db):
    fo, fw = create_fw_with_child_fo()
    assert common_db.exists(fo.uid) is False
    assert common_db.exists(fw.uid) is False
    backend_db.insert_object(fw)
    backend_db.insert_object(fo)
    assert common_db.exists(fo.uid) is True
    assert common_db.exists(fw.uid) is True
    admin_db.delete_object(fw.uid)
    assert common_db.exists(fw.uid) is False
    assert common_db.exists(fo.uid) is False, 'deletion should be cascaded to child objects'


def test_remove_vp_no_other_fw(admin_db, common_db, backend_db):
    fo, fw = create_fw_with_child_fo()
    backend_db.insert_object(fw)
    backend_db.insert_object(fo)

    with admin_db.get_read_write_session() as session:
        removed_vps, deleted_uids = admin_db._remove_virtual_path_entries(
            fw.uid, fo.uid, session
        )  # pylint: disable=protected-access

    assert removed_vps == 0
    assert deleted_uids == {fo.uid}


def test_remove_vp_other_fw(admin_db, common_db, backend_db):
    fo, fw = create_fw_with_child_fo()
    fo.virtual_file_path.update({'some_other_fw_uid': ['some_vfp']})
    backend_db.insert_object(fw)
    backend_db.insert_object(fo)

    with admin_db.get_read_write_session() as session:
        removed_vps, deleted_files = admin_db._remove_virtual_path_entries(
            fw.uid, fo.uid, session
        )  # pylint: disable=protected-access
    fo_entry = common_db.get_object(fo.uid)

    assert fo_entry is not None
    assert removed_vps == 1
    assert deleted_files == set()
    assert fw.uid not in fo_entry.virtual_file_path


def test_delete_firmware(admin_db, common_db, backend_db):
    fw, parent, child = create_fw_with_parent_and_child()
    backend_db.insert_object(fw)
    backend_db.insert_object(parent)
    backend_db.insert_object(child)

    removed_vps, deleted_files = admin_db.delete_firmware(fw.uid)

    assert removed_vps == 0
    assert deleted_files == 3
    assert child.uid in admin_db.intercom.deleted_files
    assert parent.uid in admin_db.intercom.deleted_files
    assert fw.uid in admin_db.intercom.deleted_files
    assert common_db.exists(fw.uid) is False
    assert common_db.exists(parent.uid) is False, 'should have been deleted by cascade'
    assert common_db.exists(child.uid) is False, 'should have been deleted by cascade'


def test_delete_but_fo_is_in_fw(admin_db, common_db, backend_db):
    fo, fw = create_fw_with_child_fo()
    fw2 = create_test_firmware()
    fw2.uid = 'fw2_uid'
    fo.parents.append(fw2.uid)
    fo.virtual_file_path.update({fw2.uid: [f'|{fw2.uid}|/some/path']})
    backend_db.insert_object(fw)
    backend_db.insert_object(fw2)
    backend_db.insert_object(fo)

    removed_vps, deleted_files = admin_db.delete_firmware(fw.uid)

    assert removed_vps == 1
    assert deleted_files == 1
    assert fo.uid not in admin_db.intercom.deleted_files
    fo_entry = common_db.get_object(fo.uid)
    assert fw.uid not in fo_entry.virtual_file_path
    assert fw2.uid in fo_entry.virtual_file_path
    assert fw.uid in admin_db.intercom.deleted_files
    assert common_db.exists(fw.uid) is False
    assert common_db.exists(fo.uid) is True, 'should have been spared by cascade delete because it is in another FW'
