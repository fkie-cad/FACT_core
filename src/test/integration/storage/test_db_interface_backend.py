from copy import deepcopy

import pytest

from test.common_helper import create_test_file_object, create_test_firmware  # pylint: disable=wrong-import-order

from .helper import TEST_FO, TEST_FW, create_fw_with_child_fo


def test_insert_objects(db):
    db.backend.insert_file_object(TEST_FO)
    db.backend.insert_firmware(TEST_FW)


def test_insert_fw_w_big_size(db):
    fw = deepcopy(TEST_FW)
    fw.size = 2_352_167_575
    db.backend.insert_firmware(fw)


@pytest.mark.parametrize('fw_object', [TEST_FW, TEST_FO])
def test_insert(db, fw_object):
    db.backend.insert_object(fw_object)
    assert db.common.exists(fw_object.uid)


def test_update_parents(db):
    fo, fw = create_fw_with_child_fo()
    db.backend.insert_object(fw)
    db.backend.insert_object(fo)

    fo_db = db.common.get_object(fo.uid)
    assert fo_db.parents == {fw.uid}
    assert fo_db.parent_firmware_uids == {fw.uid}

    fw2 = create_test_firmware()
    fw2.uid = 'test_fw2'
    db.backend.insert_object(fw2)
    db.backend.update_file_object_parents(fo.uid, fw2.uid, fw2.uid)

    fo_db = db.common.get_object(fo.uid)
    assert fo_db.parents == {fw.uid, fw2.uid}


def test_update_duplicate_other_fw(db):
    # fo is included in another fw -> check if update of entry works correctly
    fo, fw = create_fw_with_child_fo()
    db.backend.add_object(fw)
    db.backend.add_object(fo)

    fw2 = create_test_firmware()
    fw2.uid = 'test_fw2'
    fw2.files_included = [fo.uid]
    fo2 = create_test_file_object()
    fo2.uid = fo.uid
    fo2.virtual_file_path = {fw2.uid: [f'{fw2.uid}|/some/path']}
    fo2.parents = {fw2.uid}

    db.backend.add_object(fw2)
    db.backend.add_object(fo2)

    db_fo = db.frontend.get_object(fo2.uid)
    assert db_fo.virtual_file_path == {
        fw.uid: [fo.virtual_file_path[fw.uid][0]],
        fw2.uid: [fo2.virtual_file_path[fw2.uid][0]],
    }
    assert db_fo.parents == {fw.uid, fw2.uid}
    assert db_fo.parent_firmware_uids == {fw.uid, fw2.uid}


def test_update_duplicate_same_fw(db):
    # fo is included multiple times in the same fw -> check if update of entry works correctly
    fo, fw = create_fw_with_child_fo()
    db.backend.add_object(fw)
    db.backend.add_object(fo)

    fo.virtual_file_path[fw.uid].append(f'{fw.uid}|/some/other/path')
    db.backend.add_object(fo)

    db_fo = db.frontend.get_object(fo.uid)
    assert list(db_fo.virtual_file_path) == [fw.uid]
    assert len(db_fo.virtual_file_path[fw.uid]) == 2
    assert db_fo.parents == {fw.uid}


def test_analysis_exists(db):
    assert db.backend.analysis_exists(TEST_FO.uid, 'file_type') is False
    db.backend.insert_file_object(TEST_FO)
    assert db.backend.analysis_exists(TEST_FO.uid, 'file_type') is True


def test_update_file_object(db):
    fo = create_test_file_object()
    fo.comments = [{'author': 'anonymous', 'comment': 'foobar 123', 'time': '1599726695'}]
    db.backend.insert_object(fo)
    db_fo = db.common.get_object(fo.uid)
    assert db_fo.comments == fo.comments
    assert db_fo.file_name == fo.file_name

    fo.file_name = 'foobar.exe'
    fo.comments = [
        {'author': 'anonymous', 'comment': 'foobar 123', 'time': '1599726695'},
        {'author': 'someguy', 'comment': 'this file is something!', 'time': '1636448202'},
    ]
    db.backend.update_object(fo)
    db_fo = db.common.get_object(fo.uid)
    assert db_fo.file_name == fo.file_name
    assert db_fo.comments == fo.comments


def test_update_firmware(db):
    fw = create_test_firmware()
    db.backend.insert_object(fw)
    db_fw = db.common.get_object(fw.uid)
    assert db_fw.device_name == fw.device_name
    assert db_fw.vendor == fw.vendor
    assert db_fw.file_name == fw.file_name

    fw.vendor = 'different vendor'
    fw.device_name = 'other device'
    fw.file_name = 'foobar.exe'
    db.backend.update_object(fw)
    db_fw = db.common.get_object(fw.uid)
    assert db_fw.device_name == fw.device_name
    assert db_fw.vendor == fw.vendor
    assert db_fw.file_name == fw.file_name


def test_insert_analysis(db):
    db.backend.insert_file_object(TEST_FO)
    plugin = 'previously_not_run_plugin'
    new_analysis_data = {
        'summary': ['sum 1', 'sum 2'],
        'foo': 'bar',
        'plugin_version': '1',
        'analysis_date': 1.0,
        'tags': {},
        'system_version': '1.2',
    }
    db.backend.add_analysis(TEST_FO.uid, plugin, new_analysis_data)
    db_fo = db.common.get_object(TEST_FO.uid)
    assert plugin in db_fo.processed_analysis
    assert db_fo.processed_analysis[plugin] == new_analysis_data


def test_update_analysis(db):
    db.backend.insert_file_object(TEST_FO)
    updated_analysis_data = {'summary': ['sum b'], 'content': 'file efgh', 'plugin_version': '1', 'analysis_date': 1.0}
    db.backend.add_analysis(TEST_FO.uid, 'dummy', updated_analysis_data)
    analysis = db.common.get_analysis(TEST_FO.uid, 'dummy')
    assert analysis is not None
    assert analysis['content'] == 'file efgh'
    assert analysis['summary'] == updated_analysis_data['summary']
    assert analysis['plugin_version'] == updated_analysis_data['plugin_version']
