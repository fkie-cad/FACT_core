from copy import deepcopy

import pytest

from storage.db_interface_base import DbInterfaceError
from test.common_helper import create_test_file_object, create_test_firmware

from .helper import TEST_FO, TEST_FW, add_included_file, create_fw_with_child_fo, create_fw_with_parent_and_child


def test_insert_objects(backend_db):
    backend_db.insert_file_object(TEST_FO)
    backend_db.insert_firmware(TEST_FW)


def test_insert_fw_w_big_size(backend_db):
    fw = deepcopy(TEST_FW)
    fw.size = 2_352_167_575
    backend_db.insert_firmware(fw)


@pytest.mark.parametrize('fw_object', [TEST_FW, TEST_FO])
def test_insert(backend_db, common_db, fw_object):
    backend_db.insert_object(fw_object)
    assert common_db.exists(fw_object.uid)


def test_update_parents(backend_db, common_db):
    fo, fw = create_fw_with_child_fo()
    backend_db.insert_multiple_objects(fw, fo)

    fo_db = common_db.get_object(fo.uid)
    assert fo_db.parents == {fw.uid}
    assert fo_db.parent_firmware_uids == {fw.uid}

    fw2 = create_test_firmware()
    fw2.uid = 'test_fw2'
    backend_db.insert_object(fw2)
    backend_db.update_file_object_parents(fo.uid, fw2.uid, fw2.uid)

    fo_db = common_db.get_object(fo.uid)
    assert fo_db.parents == {fw.uid, fw2.uid}


def test_add_vfp(backend_db, admin_db):
    fw, parent_fo, child_fo = create_fw_with_parent_and_child()
    backend_db.insert_multiple_objects(fw, parent_fo, child_fo)

    assert len(backend_db.get_vfps(child_fo.uid)) == 1

    paths = ['foo/bar', 'test']
    backend_db.add_vfp(fw.uid, child_fo.uid, paths)
    backend_db.add_child_to_parent(fw.uid, child_fo.uid)
    vfp_dict = backend_db.get_vfps(child_fo.uid)

    assert set(vfp_dict) == {fw.uid, parent_fo.uid}
    assert sorted(vfp_dict[fw.uid]) == paths

    # add another path
    updated_paths = ['/new/path']
    backend_db.add_vfp(fw.uid, child_fo.uid, updated_paths)
    vfp_dict = backend_db.get_vfps(child_fo.uid)
    assert sorted(vfp_dict[fw.uid]) == updated_paths + paths

    # trying to add a duplicate should not cause an exception
    backend_db.add_vfp(fw.uid, child_fo.uid, updated_paths)
    backend_db.add_child_to_parent(fw.uid, child_fo.uid)

    admin_db.delete_firmware(fw.uid)
    assert backend_db.get_vfps(child_fo.uid) == {}, 'VFP should have been deleted by cascade'


def test_vfp_multiple_parents(common_db, backend_db, admin_db):
    fw, parent_fo, fo = create_fw_with_parent_and_child()
    fo.virtual_file_path = {parent_fo.uid: ['foo']}
    fw2 = create_test_firmware()
    fw2.uid = 'test_fw2'
    for obj in [fw, fw2, parent_fo, fo]:
        backend_db.insert_object(obj)

    assert set(common_db.get_vfps(fo.uid)) == {parent_fo.uid}

    backend_db.add_vfp(fw2.uid, fo.uid, ['bar'])
    assert common_db.get_vfps(fo.uid) == {parent_fo.uid: ['foo'], fw2.uid: ['bar']}
    assert common_db.get_vfps(fo.uid, parent_uid=parent_fo.uid) == {parent_fo.uid: ['foo']}
    assert common_db.get_vfps(fo.uid, parent_uid=fw2.uid) == {fw2.uid: ['bar']}

    assert common_db.get_vfps(fo.uid, root_uid=fw.uid) == {parent_fo.uid: ['foo']}
    assert common_db.get_vfps(fo.uid, root_uid=fw2.uid) == {fw2.uid: ['bar']}

    admin_db.delete_firmware(fw2.uid)
    assert common_db.get_vfps(fo.uid) == {parent_fo.uid: ['foo']}, 'fw2 VFP should have been deleted by cascade'


def test_object_conversion_vfp(common_db, backend_db, admin_db):
    fw, parent_fo, child_fo = create_fw_with_parent_and_child()
    backend_db.insert_multiple_objects(fw, parent_fo, child_fo)

    parent_vfp = backend_db.get_vfps(parent_fo.uid)
    parent_from_db = common_db.get_object(parent_fo.uid)
    assert parent_vfp == {fw.uid: [f'/folder/{parent_fo.file_name}']}
    assert parent_from_db.virtual_file_path == parent_vfp, 'result of obj conversion and get_vfps() should be the same'

    child_from_db = common_db.get_object(child_fo.uid)
    assert child_from_db.virtual_file_path == {parent_fo.uid: [f'/folder/{child_fo.file_name}']}

    admin_db.delete_firmware(fw.uid)
    assert backend_db.get_vfps(child_fo.uid) == {}, 'VFP should have been deleted by cascade'


def test_update_duplicate_other_fw(backend_db, frontend_db):
    # fo is included in another fw -> check if update of entry works correctly
    fo, fw = create_fw_with_child_fo()
    backend_db.insert_multiple_objects(fw, fo)

    fw2 = create_test_firmware()
    fw2.uid = 'test_fw2'
    fo2 = create_test_file_object(uid=fo.uid)
    add_included_file(fo2, fw2, fw2, ['/some/path'])

    backend_db.add_object(fw2)
    backend_db.add_object(fo2)

    db_fo = frontend_db.get_object(fo2.uid)
    assert db_fo.virtual_file_path == {
        fw.uid: [fo.virtual_file_path[fw.uid][0]],
        fw2.uid: [fo2.virtual_file_path[fw2.uid][0]],
    }
    assert db_fo.parents == {fw.uid, fw2.uid}
    assert db_fo.parent_firmware_uids == {fw.uid, fw2.uid}


def test_update_duplicate_same_fw(backend_db, frontend_db):
    # fo is included multiple times in the same fw -> check if update of entry works correctly
    fo, fw = create_fw_with_child_fo()
    backend_db.insert_multiple_objects(fw, fo)

    fo.virtual_file_path[fw.uid].append('/some/other/path')
    backend_db.add_object(fo)

    db_fo = frontend_db.get_object(fo.uid)
    assert list(db_fo.virtual_file_path) == [fw.uid]
    assert len(db_fo.virtual_file_path[fw.uid]) == 2
    assert db_fo.parents == {fw.uid}


def test_update_duplicate_file_as_fw(backend_db):
    # special case: trying to upload a file as FW that is already in the DB as part of another FW -> should cause error
    fo, fw = create_fw_with_child_fo()
    backend_db.insert_multiple_objects(fw, fo)
    fw2 = create_test_firmware()
    fw2.uid = fo.uid

    with pytest.raises(DbInterfaceError):
        backend_db.add_object(fw2)


def test_analysis_exists(backend_db):
    assert backend_db.analysis_exists(TEST_FO.uid, 'file_type') is False
    backend_db.insert_file_object(TEST_FO)
    assert backend_db.analysis_exists(TEST_FO.uid, 'file_type') is True


def test_update_file_object(backend_db, common_db):
    fo = create_test_file_object()
    fo.comments = [{'author': 'anonymous', 'comment': 'foobar 123', 'time': '1599726695'}]
    backend_db.insert_object(fo)
    db_fo = common_db.get_object(fo.uid)
    assert db_fo.comments == fo.comments
    assert db_fo.file_name == fo.file_name

    fo.file_name = 'foobar.exe'
    fo.comments = [
        {'author': 'anonymous', 'comment': 'foobar 123', 'time': '1599726695'},
        {'author': 'someguy', 'comment': 'this file is something!', 'time': '1636448202'},
    ]
    backend_db.update_object(fo)
    db_fo = common_db.get_object(fo.uid)
    assert db_fo.file_name == fo.file_name
    assert db_fo.comments == fo.comments


def test_update_firmware(backend_db, common_db):
    fw = create_test_firmware()
    backend_db.insert_object(fw)
    db_fw = common_db.get_object(fw.uid)
    assert db_fw.device_name == fw.device_name
    assert db_fw.vendor == fw.vendor
    assert db_fw.file_name == fw.file_name

    fw.vendor = 'different vendor'
    fw.device_name = 'other device'
    fw.file_name = 'foobar.exe'
    backend_db.update_object(fw)
    db_fw = common_db.get_object(fw.uid)
    assert db_fw.device_name == fw.device_name
    assert db_fw.vendor == fw.vendor
    assert db_fw.file_name == fw.file_name


def test_insert_analysis(backend_db, common_db):
    backend_db.insert_file_object(TEST_FO)
    plugin = 'previously_not_run_plugin'
    new_analysis_data = {
        'summary': ['sum 1', 'sum 2'],
        'result': {
            'foo': 'bar',
        },
        'plugin_version': '1',
        'analysis_date': 1.0,
        'tags': {},
        'system_version': '1.2',
    }
    backend_db.add_analysis(TEST_FO.uid, plugin, new_analysis_data)
    db_fo = common_db.get_object(TEST_FO.uid)
    assert plugin in db_fo.processed_analysis
    assert db_fo.processed_analysis[plugin] == new_analysis_data


def test_insert_analysis_error(backend_db, common_db):
    backend_db.insert_file_object(TEST_FO)
    illegal_analysis = {
        'analysis_date': 1.0,
        'plugin_version': '0.1.0',
        'system_version': '0.1.0',
        'summary': [],
        'tags': {},
        'result': {'key': ('a', 'b\0'), 'foo': 'bar\0'},
    }
    plugin = 'foo'
    backend_db.add_analysis(TEST_FO.uid, plugin, illegal_analysis)
    db_fo = common_db.get_object(TEST_FO.uid)
    assert db_fo.processed_analysis[plugin]['result'] == {'foo': 'bar', 'key': ['a', 'b']}


def test_update_analysis(backend_db, common_db):
    backend_db.insert_file_object(TEST_FO)
    updated_analysis_data = {
        'summary': ['sum b'],
        'result': {'content': 'file efgh'},
        'plugin_version': '1',
        'analysis_date': 1.0,
    }
    backend_db.add_analysis(TEST_FO.uid, 'dummy', updated_analysis_data)
    analysis = common_db.get_analysis(TEST_FO.uid, 'dummy')
    assert analysis is not None
    assert analysis['result']['content'] == 'file efgh'
    assert analysis['summary'] == updated_analysis_data['summary']
    assert analysis['plugin_version'] == updated_analysis_data['plugin_version']


def test_get_parent_fw(backend_db, common_db):
    fw, parent_fo, child_fo = create_fw_with_parent_and_child()
    fw2 = create_test_firmware()
    fw2.uid = 'test_fw2'
    add_included_file(child_fo, fw2, fw2, ['/some/path'])
    backend_db.insert_multiple_objects(fw, fw2, parent_fo, child_fo)

    root_fw = common_db.get_parent_fw(child_fo.uid)
    assert root_fw == {fw.uid, fw2.uid}

    root_fw_dict = common_db.get_parent_fw_for_uid_list([fw.uid, parent_fo.uid, child_fo.uid])
    assert root_fw_dict == {
        parent_fo.uid: {fw.uid},
        child_fo.uid: {fw.uid, fw2.uid},
    }
