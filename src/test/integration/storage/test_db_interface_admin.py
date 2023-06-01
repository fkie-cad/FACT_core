from ...common_helper import create_test_file_object, create_test_firmware
from .helper import TEST_FW, create_fw_with_child_fo, create_fw_with_parent_and_child


def test_delete_fo(db):
    assert db.common.exists(TEST_FW.uid) is False
    db.backend.insert_object(TEST_FW)
    assert db.common.exists(TEST_FW.uid) is True
    db.admin.delete_object(TEST_FW.uid)
    assert db.common.exists(TEST_FW.uid) is False


def test_delete_cascade(db):
    fo, fw = create_fw_with_child_fo()
    assert db.common.exists(fo.uid) is False
    assert db.common.exists(fw.uid) is False
    db.backend.insert_multiple_objects(fw, fo)
    assert db.common.exists(fo.uid) is True
    assert db.common.exists(fw.uid) is True
    db.admin.delete_object(fw.uid)
    assert db.common.exists(fw.uid) is False
    assert db.common.exists(fo.uid) is False, 'deletion should be cascaded to child objects'


def test_delete_firmware(db):
    fw, parent, child = create_fw_with_parent_and_child()
    db.backend.insert_multiple_objects(fw, parent, child)
    db.admin.delete_firmware(fw.uid)

    assert db.common.exists(fw.uid) is False
    assert db.common.exists(parent.uid) is False, 'should have been deleted by cascade'
    assert db.common.exists(child.uid) is False, 'should have been deleted by cascade'


def test_delete_but_fo_is_in_fw(db):
    fo, fw = create_fw_with_child_fo()
    fw2 = create_test_firmware()
    fw2.uid = 'fw2_uid'
    fo.parents.append(fw2.uid)
    fo.parent_firmware_uids.add(fw2.uid)
    fo.virtual_file_path.update({fw2.uid: [f'|{fw2.uid}|/some/path']})
    db.backend.insert_multiple_objects(fw, fw2, fo)

    removed_vps, deleted_files = db.admin.delete_firmware(fw.uid)

    assert removed_vps == 1
    assert deleted_files == 1
    assert fo.uid not in db.admin.intercom.deleted_files
    fo_entry = db.common.get_object(fo.uid)
    assert fw.uid not in fo_entry.virtual_file_path
    assert fw2.uid in fo_entry.virtual_file_path
    assert fw.uid in db.admin.intercom.deleted_files
    assert db.common.exists(fw.uid) is False
    assert db.common.exists(fo.uid) is True, 'should have been spared by cascade delete because it is in another FW'
    fo_db = db.common.get_object(fo.uid)
    assert fo_db.virtual_file_path == {'fw2_uid': ['|fw2_uid|/some/path']}, 'entry of fw should be deleted from vfp'


def test_same_fw_multiple_parents(db):
    fw, parent, child = create_fw_with_parent_and_child()
    parent2 = create_test_file_object()
    parent2.uid = 'parent2'
    parent2.parents.append(fw.uid)
    parent2.parent_firmware_uids.add(fw.uid)
    # child has multiple parents but all in the same FW -> should still be deleted by cascade
    child.parents.append(parent2.uid)
    db.backend.insert_multiple_objects(fw, parent, parent2, child)

    db.admin.delete_firmware(fw.uid)

    assert db.common.exists(fw.uid) is False
    assert db.common.exists(parent.uid) is False, 'should have been deleted by cascade'
    assert db.common.exists(parent2.uid) is False, 'should have been deleted by cascade'
    assert db.common.exists(child.uid) is False, 'should have been deleted by cascade'
