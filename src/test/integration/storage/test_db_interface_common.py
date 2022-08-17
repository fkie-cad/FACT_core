# pylint: disable=protected-access,invalid-name,wrong-import-order

from objects.file import FileObject
from objects.firmware import Firmware
from test.common_helper import create_test_file_object, create_test_firmware, generate_analysis_entry

from .helper import (
    TEST_FO,
    TEST_FO_2,
    TEST_FW,
    create_fw_with_child_fo,
    create_fw_with_parent_and_child,
    insert_test_fo,
)


def test_init(db):  # pylint: disable=unused-argument
    assert True


def test_get_file(db):
    assert db.common.get_file_object(TEST_FO.uid) is None
    db.backend.insert_object(TEST_FO)
    db_fo = db.common.get_file_object(TEST_FO.uid)
    assert isinstance(db_fo, FileObject) and not isinstance(db_fo, Firmware)
    fo_attributes = ['uid', 'file_name', 'size', 'depth']
    assert all(getattr(TEST_FO, attr) == getattr(db_fo, attr) for attr in fo_attributes)
    assert set(db_fo.processed_analysis) == set(TEST_FO.processed_analysis)


def test_get_file_filtered(db):
    db.backend.insert_object(TEST_FO)
    db_fo = db.common.get_file_object(TEST_FO.uid, analysis_filter=['unpacker'])
    assert list(db_fo.processed_analysis) == ['unpacker']
    db_fo = db.common.get_file_object(TEST_FO.uid, analysis_filter=['file_type', 'dummy'])
    assert sorted(db_fo.processed_analysis) == ['dummy', 'file_type']
    db_fo = db.common.get_file_object(TEST_FO.uid, analysis_filter=['unknown plugin'])
    assert not list(db_fo.processed_analysis)


def test_get_fw(db):
    assert db.common.get_firmware(TEST_FW.uid) is None
    db.backend.insert_object(TEST_FW)
    db_fw = db.common.get_firmware(TEST_FW.uid)
    assert isinstance(db_fw, Firmware)
    fw_attributes = ['uid', 'vendor', 'device_name', 'release_date']
    assert all(getattr(TEST_FW, attr) == getattr(db_fw, attr) for attr in fw_attributes)
    assert set(db_fw.processed_analysis) == set(TEST_FW.processed_analysis)


def test_get_object_fw(db):
    assert db.common.get_object(TEST_FW.uid) is None
    db.backend.insert_object(TEST_FW)
    db_fw = db.common.get_object(TEST_FW.uid)
    assert isinstance(db_fw, Firmware)


def test_get_object_fo(db):
    assert db.common.get_object(TEST_FO.uid) is None
    db.backend.insert_object(TEST_FO)
    db_fo = db.common.get_object(TEST_FO.uid)
    assert not isinstance(db_fo, Firmware)
    assert isinstance(db_fo, FileObject)


def test_exists_fo(db):
    assert db.common.exists(TEST_FO.uid) is False
    db.backend.insert_object(TEST_FO)
    assert db.common.exists(TEST_FO.uid) is True


def test_exists_fw(db):
    assert db.common.exists(TEST_FW.uid) is False
    db.backend.insert_object(TEST_FW)
    assert db.common.exists(TEST_FW.uid) is True


def test_is_fw(db):
    assert db.common.is_firmware(TEST_FW.uid) is False
    db.backend.insert_object(TEST_FO)
    assert db.common.is_firmware(TEST_FO.uid) is False
    db.backend.insert_object(TEST_FW)
    assert db.common.is_firmware(TEST_FW.uid) is True


def test_get_object_relationship(db):
    fo, fw = create_fw_with_child_fo()

    db.backend.insert_object(fw)
    db.backend.insert_object(fo)
    db_fo = db.common.get_object(fo.uid)
    db_fw = db.common.get_object(fw.uid)
    assert db_fo.parents == {fw.uid}
    assert db_fo.parent_firmware_uids == {fw.uid}
    assert db_fw.files_included == {fo.uid}


def test_all_files_in_fw(db):
    fw, parent_fo, child_fo = create_fw_with_parent_and_child()
    db.backend.insert_object(fw)
    db.backend.insert_object(parent_fo)
    db.backend.insert_object(child_fo)
    assert db.common.get_all_files_in_fw(fw.uid) == {child_fo.uid, parent_fo.uid}


def test_all_files_in_fo(db):
    fw, parent_fo, child_fo = create_fw_with_parent_and_child()
    db.backend.insert_object(fw)
    db.backend.insert_object(parent_fo)
    db.backend.insert_object(child_fo)
    assert db.common.get_all_files_in_fo(fw) == {fw.uid, parent_fo.uid, child_fo.uid}
    assert db.common.get_all_files_in_fo(parent_fo) == {parent_fo.uid, child_fo.uid}


def test_get_objects_by_uid_list(db):
    fo, fw = create_fw_with_child_fo()
    db.backend.insert_object(fw)
    db.backend.insert_object(fo)
    result = db.common.get_objects_by_uid_list([fo.uid, fw.uid])
    assert len(result) == 2
    objects_by_uid = {fo.uid: fo for fo in result}
    assert fo.uid in objects_by_uid and fw.uid in objects_by_uid
    assert isinstance(objects_by_uid[fw.uid], Firmware)
    assert isinstance(objects_by_uid[fo.uid], FileObject)


def test_get_analysis(db):
    db.backend.insert_object(TEST_FW)
    result = db.common.get_analysis(TEST_FW.uid, 'file_type')
    assert isinstance(result, dict)
    assert result['mime'] == TEST_FW.processed_analysis['file_type']['mime']
    assert result['summary'] == TEST_FW.processed_analysis['file_type']['summary']
    assert result['analysis_date'] == TEST_FW.processed_analysis['file_type']['analysis_date']
    assert result['plugin_version'] == TEST_FW.processed_analysis['file_type']['plugin_version']
    assert result['system_version'] is None


def test_get_complete_object(db):
    fw, parent_fo, child_fo = create_fw_with_parent_and_child()
    fw.processed_analysis['test_plugin'] = generate_analysis_entry(summary=['entry0'])
    parent_fo.processed_analysis['test_plugin'] = generate_analysis_entry(summary=['entry1', 'entry2'])
    child_fo.processed_analysis['test_plugin'] = generate_analysis_entry(summary=['entry2', 'entry3'])
    db.backend.insert_object(fw)
    db.backend.insert_object(parent_fo)
    db.backend.insert_object(child_fo)

    result = db.common.get_complete_object_including_all_summaries(fw.uid)
    assert isinstance(result, Firmware)
    assert result.uid == fw.uid
    expected_summary = {
        'entry0': [fw.uid],
        'entry1': [parent_fo.uid],
        'entry2': [parent_fo.uid, child_fo.uid],
        'entry3': [child_fo.uid],
    }
    _summary_is_equal(expected_summary, result.processed_analysis['test_plugin']['summary'])

    result = db.common.get_complete_object_including_all_summaries(parent_fo.uid)
    assert isinstance(result, FileObject)
    expected_summary = {
        'entry1': [parent_fo.uid],
        'entry2': [parent_fo.uid, child_fo.uid],
        'entry3': [child_fo.uid],
    }
    _summary_is_equal(expected_summary, result.processed_analysis['test_plugin']['summary'])


def _summary_is_equal(expected_summary, summary):
    assert all(key in summary for key in expected_summary)
    assert all(set(expected_summary[key]) == set(summary[key]) for key in expected_summary)


def test_all_uids_found_in_database(db):
    db.backend.insert_object(TEST_FW)
    assert db.common.all_uids_found_in_database([TEST_FW.uid]) is True
    assert db.common.all_uids_found_in_database([TEST_FW.uid, TEST_FO.uid]) is False
    db.backend.insert_object(TEST_FO)
    assert db.common.all_uids_found_in_database([TEST_FW.uid, TEST_FO.uid]) is True


def test_get_firmware_number(db):
    assert db.common.get_firmware_number() == 0

    db.backend.insert_object(TEST_FW)
    assert db.common.get_firmware_number(query={}) == 1
    assert db.common.get_firmware_number(query={'uid': TEST_FW.uid}) == 1

    fw_2 = create_test_firmware(bin_path='container/test.7z')
    db.backend.insert_object(fw_2)
    assert db.common.get_firmware_number(query={}) == 2
    assert db.common.get_firmware_number(query={'device_class': 'Router'}) == 2
    assert db.common.get_firmware_number(query={'uid': TEST_FW.uid}) == 1
    assert db.common.get_firmware_number(query={'sha256': TEST_FW.sha256}) == 1


def test_get_file_object_number(db):
    assert db.common.get_file_object_number({}) == 0

    db.backend.insert_object(TEST_FO)
    assert db.common.get_file_object_number(query={}, zero_on_empty_query=False) == 1
    assert db.common.get_file_object_number(query={'uid': TEST_FO.uid}) == 1
    assert db.common.get_file_object_number(query={}, zero_on_empty_query=True) == 0

    db.backend.insert_object(TEST_FO_2)
    assert db.common.get_file_object_number(query={}, zero_on_empty_query=False) == 2
    assert db.common.get_file_object_number(query={'uid': TEST_FO.uid}) == 1


def test_get_summary(db):
    fo, fw = create_fw_with_child_fo()
    db.backend.insert_object(fw)
    db.backend.insert_object(fo)

    result_sum = db.common.get_summary(fw, 'dummy')
    assert isinstance(result_sum, dict), 'summary is not a dict'
    assert 'sum a' in result_sum, 'summary entry of parent missing'
    assert fw.uid in result_sum['sum a'], 'origin (parent) missing in parent summary entry'
    assert fo.uid in result_sum['sum a'], 'origin (child) missing in parent summary entry'
    assert fo.uid not in result_sum['fw exclusive sum a'], 'child as origin but should not be'
    assert 'file exclusive sum b' in result_sum, 'file exclusive summary missing'
    assert fo.uid in result_sum['file exclusive sum b'], 'origin of file exclusive missing'
    assert fw.uid not in result_sum['file exclusive sum b'], 'parent as origin but should not be'


def test_collect_summary(db):
    fo, fw = create_fw_with_child_fo()
    db.backend.insert_object(fw)
    db.backend.insert_object(fo)
    fo_list = [fo.uid]
    result_sum = db.common._collect_summary(fo_list, 'dummy')
    assert all(item in result_sum for item in fo.processed_analysis['dummy']['summary'])
    assert all(value == [fo.uid] for value in result_sum.values())


def test_get_summary_of_one_error_handling(db):
    fo, fw = create_fw_with_child_fo()
    db.backend.insert_object(fw)
    db.backend.insert_object(fo)

    result_sum = db.common._get_summary_of_one(None, 'foo')
    assert result_sum == {}, 'None object should result in empty dict'
    result_sum = db.common._get_summary_of_one(fw, 'non_existing_analysis')
    assert result_sum == {}, 'analysis non-existent should lead to empty dict'


def test_update_summary(db):
    orig = {'a': ['a']}
    update = {'a': ['aa'], 'b': ['aa']}
    db.common._update_summary(orig, update)
    assert 'a' in orig
    assert 'b' in orig
    assert 'a' in orig['a']
    assert 'aa' in orig['a']
    assert 'aa' in orig['b']


def test_collect_child_tags_propagate(db):
    fo, fw = create_fw_with_child_fo()
    tag = {'OS Version': {'color': 'success', 'value': 'FactOS', 'propagate': True}}
    fo.processed_analysis['software_components'] = generate_analysis_entry(tags=tag)
    db.backend.insert_object(fw)
    db.backend.insert_object(fo)
    assert db.common._collect_analysis_tags_from_children(fw.uid) == {'software_components': tag}


def test_collect_child_tags_no_propagate(db):
    fo, fw = create_fw_with_child_fo()
    tag = {'OS Version': {'color': 'success', 'value': 'FactOS', 'propagate': False}}
    fo.processed_analysis['software_components'] = generate_analysis_entry(tags=tag)
    db.backend.insert_object(fw)
    db.backend.insert_object(fo)
    assert db.common._collect_analysis_tags_from_children(fw.uid) == {}


def test_collect_child_tags_no_tags(db):
    fo, fw = create_fw_with_child_fo()
    fo.processed_analysis['software_components'] = generate_analysis_entry(tags={})
    db.backend.insert_object(fw)
    db.backend.insert_object(fo)
    assert db.common._collect_analysis_tags_from_children(fw.uid) == {}


def test_collect_child_tags_duplicate(db):
    fo, fw = create_fw_with_child_fo()
    tag = {'OS Version': {'color': 'success', 'value': 'FactOS 1.1', 'propagate': True}}
    fo.processed_analysis['software_components'] = generate_analysis_entry(tags=tag)
    fo_2 = create_test_file_object('get_files_test/testfile2')
    fo_2.processed_analysis['software_components'] = generate_analysis_entry(tags=tag)
    fo_2.parent_firmware_uids.add(fw.uid)
    db.backend.insert_object(fw)
    db.backend.insert_object(fo)
    db.backend.insert_object(fo_2)

    assert db.common._collect_analysis_tags_from_children(fw.uid) == {'software_components': tag}


def test_collect_child_tags_unique_tags(db):
    fo, fw = create_fw_with_child_fo()
    tags = {'OS Version': {'color': 'success', 'value': 'FactOS 1.1', 'propagate': True}}
    fo.processed_analysis['software_components'] = generate_analysis_entry(tags=tags)
    fo_2 = create_test_file_object('get_files_test/testfile2')
    tags = {'OS Version': {'color': 'success', 'value': 'OtherOS 0.2', 'propagate': True}}
    fo_2.processed_analysis['software_components'] = generate_analysis_entry(tags=tags)
    fo_2.parent_firmware_uids.add(fw.uid)
    db.backend.insert_object(fw)
    db.backend.insert_object(fo)
    db.backend.insert_object(fo_2)

    assert len(db.common._collect_analysis_tags_from_children(fw.uid)['software_components']) == 2


def test_collect_analysis_tags(db):
    tags1 = {
        'tag_a': {
            'color': 'success', 'value': 'tag a', 'propagate': True
        },
        'tag_b': {
            'color': 'warning', 'value': 'tag b', 'propagate': False
        },
    }
    tags2 = {'tag_c': {'color': 'success', 'value': 'tag c', 'propagate': True}}
    insert_test_fo(
        db,
        'fo1',
        analysis={
            'foo': generate_analysis_entry(tags=tags1),
            'bar': generate_analysis_entry(tags=tags2),
        },
    )

    fo = db.frontend.get_object('fo1')
    assert 'foo' in fo.analysis_tags and 'bar' in fo.analysis_tags
    assert set(fo.analysis_tags['foo']) == {'tag_a', 'tag_b'}
    assert fo.analysis_tags['foo']['tag_a'] == tags1['tag_a']
