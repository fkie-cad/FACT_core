import pytest

from test.common_helper import create_test_file_object, create_test_firmware  # pylint: disable=wrong-import-order

from .helper import TEST_FO, TEST_FW, create_fw_with_child_fo


def test_insert_objects(db):
    db.backend.insert_file_object(TEST_FO)
    db.backend.insert_firmware(TEST_FW)


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
    # assert fo_db.parent_firmware_uids == {fw.uid, fw2.uid}  # FixMe? update VFP?


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
        'summary': ['sum 1', 'sum 2'], 'foo': 'bar', 'plugin_version': '1', 'analysis_date': 1.0, 'tags': {},
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
    assert analysis.result['content'] == 'file efgh'
    assert analysis.summary == updated_analysis_data['summary']
    assert analysis.plugin_version == updated_analysis_data['plugin_version']
