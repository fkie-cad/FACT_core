# pylint: disable=protected-access,invalid-name,wrong-import-order

from objects.file import FileObject
from objects.firmware import Firmware
from test.common_helper import create_test_file_object, create_test_firmware, generate_analysis_entry

from .helper import (
    TEST_FO,
    TEST_FO_2,
    TEST_FW,
    add_included_file,
    create_fw_with_child_fo,
    create_fw_with_parent_and_child,
    get_fo_with_2_root_fw,
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
    db.backend.insert_multiple_objects(fw, fo)

    db_fo = db.common.get_object(fo.uid)
    db_fw = db.common.get_object(fw.uid)
    assert db_fo.parents == {fw.uid}
    assert db_fo.parent_firmware_uids == {fw.uid}
    assert db_fw.files_included == {fo.uid}


def test_all_files_in_fw(db):
    fw, parent_fo, child_fo = create_fw_with_parent_and_child()
    db.backend.insert_multiple_objects(fw, parent_fo, child_fo)
    assert db.common.get_all_files_in_fw(fw.uid) == {child_fo.uid, parent_fo.uid}


def test_all_files_in_fo(db):
    fw, parent_fo, child_fo = create_fw_with_parent_and_child()
    db.backend.insert_multiple_objects(fw, parent_fo, child_fo)
    assert db.common.get_all_files_in_fo(fw) == {fw.uid, parent_fo.uid, child_fo.uid}
    assert db.common.get_all_files_in_fo(parent_fo) == {parent_fo.uid, child_fo.uid}


def test_get_objects_by_uid_list(db):
    fo, fw = create_fw_with_child_fo()
    db.backend.insert_multiple_objects(fw, fo)
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
    assert result['result']['mime'] == TEST_FW.processed_analysis['file_type']['result']['mime']
    assert result['summary'] == TEST_FW.processed_analysis['file_type']['summary']
    assert result['analysis_date'] == TEST_FW.processed_analysis['file_type']['analysis_date']
    assert result['plugin_version'] == TEST_FW.processed_analysis['file_type']['plugin_version']
    assert result['system_version'] is None


def test_get_complete_object(db):
    fw, parent_fo, child_fo = create_fw_with_parent_and_child()
    fw.processed_analysis['test_plugin'] = generate_analysis_entry(summary=['entry0'])
    parent_fo.processed_analysis['test_plugin'] = generate_analysis_entry(summary=['entry1', 'entry2'])
    child_fo.processed_analysis['test_plugin'] = generate_analysis_entry(summary=['entry2', 'entry3'])
    db.backend.insert_multiple_objects(fw, parent_fo, child_fo)

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
    expected_summary = {'entry1': [parent_fo.uid], 'entry2': [parent_fo.uid, child_fo.uid], 'entry3': [child_fo.uid]}
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


def test_get_summary_fw(db):
    fo, fw = create_fw_with_child_fo()
    db.backend.insert_multiple_objects(fw, fo)

    summary = db.common.get_summary(fw, 'dummy')
    assert isinstance(summary, dict), 'summary is not a dict'
    assert 'sum a' in summary, 'summary entry of parent missing'
    assert fw.uid in summary['sum a'], 'origin (parent) missing in parent summary entry'
    assert fo.uid in summary['sum a'], 'origin (child) missing in parent summary entry'
    assert fo.uid not in summary['fw exclusive sum a'], 'child as origin but should not be'
    assert 'file exclusive sum b' in summary, 'file exclusive summary missing'
    assert fo.uid in summary['file exclusive sum b'], 'origin of file exclusive missing'
    assert fw.uid not in summary['file exclusive sum b'], 'parent as origin but should not be'


def test_get_summary_fo(db):
    fw, parent_fo, child_fo = create_fw_with_parent_and_child()
    db.backend.insert_multiple_objects(fw, parent_fo, child_fo)

    summary = db.common.get_summary(parent_fo, 'dummy')
    assert parent_fo.uid in summary['sum a'], 'summary of the file itself should be included'
    assert parent_fo.uid in summary['file exclusive sum b'], 'summary of the file itself should be included'
    assert fw.uid not in summary['sum a'], 'parent summary should not be included'
    assert child_fo.uid in summary['sum a'], 'child summary should be included'
    assert child_fo.uid in summary['file exclusive sum b'], 'child summary should be included'


def test_collect_child_tags_propagate(db):
    fo, fw = create_fw_with_child_fo()
    tag = {'OS Version': {'color': 'success', 'value': 'FactOS', 'propagate': True}}
    fo.processed_analysis['software_components'] = generate_analysis_entry(tags=tag)
    db.backend.insert_multiple_objects(fw, fo)
    assert db.common._collect_analysis_tags_from_children(fw.uid) == {'software_components': tag}


def test_collect_child_tags_no_propagate(db):
    fo, fw = create_fw_with_child_fo()
    tag = {'OS Version': {'color': 'success', 'value': 'FactOS', 'propagate': False}}
    fo.processed_analysis['software_components'] = generate_analysis_entry(tags=tag)
    db.backend.insert_multiple_objects(fw, fo)
    assert db.common._collect_analysis_tags_from_children(fw.uid) == {}


def test_collect_child_tags_no_tags(db):
    fo, fw = create_fw_with_child_fo()
    fo.processed_analysis['software_components'] = generate_analysis_entry(tags={})
    db.backend.insert_multiple_objects(fw, fo)
    assert db.common._collect_analysis_tags_from_children(fw.uid) == {}


def test_collect_child_tags_duplicate(db):
    fo, fw = create_fw_with_child_fo()
    tag = {'OS Version': {'color': 'success', 'value': 'FactOS 1.1', 'propagate': True}}
    fo.processed_analysis['software_components'] = generate_analysis_entry(tags=tag)
    fo_2 = create_test_file_object('get_files_test/testfile2')
    fo_2.processed_analysis['software_components'] = generate_analysis_entry(tags=tag)
    fo_2.parent_firmware_uids.add(fw.uid)
    db.backend.insert_multiple_objects(fw, fo, fo_2)

    assert db.common._collect_analysis_tags_from_children(fw.uid) == {'software_components': tag}


def test_collect_child_tags_unique_tags(db):
    fo, fw = create_fw_with_child_fo()
    tags = {'OS Version': {'color': 'success', 'value': 'FactOS 1.1', 'propagate': True}}
    fo.processed_analysis['software_components'] = generate_analysis_entry(tags=tags)
    fo_2 = create_test_file_object('get_files_test/testfile2')
    tags = {'OS Version': {'color': 'success', 'value': 'OtherOS 0.2', 'propagate': True}}
    fo_2.processed_analysis['software_components'] = generate_analysis_entry(tags=tags)
    fo_2.parent_firmware_uids.add(fw.uid)
    db.backend.insert_multiple_objects(fw, fo, fo_2)

    assert len(db.common._collect_analysis_tags_from_children(fw.uid)['software_components']) == 2


def test_collect_analysis_tags(db):
    tags1 = {
        'tag_a': {'color': 'success', 'value': 'tag a', 'propagate': True},
        'tag_b': {'color': 'warning', 'value': 'tag b', 'propagate': False},
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


def test_get_file_tree_path(db):
    fw, parent_fo, child_fo = create_fw_with_parent_and_child()

    assert db.common.get_file_tree_path_for_uid_list([child_fo.uid]) == {child_fo.uid: []}
    assert db.common.get_file_tree_path(child_fo.uid) == []

    db.backend.insert_multiple_objects(fw, parent_fo, child_fo)

    child_path = db.common.get_file_tree_path_for_uid_list([child_fo.uid])
    assert child_path == {child_fo.uid: [[fw.uid, parent_fo.uid, child_fo.uid]]}
    assert db.common.get_file_tree_path(child_fo.uid) == [[fw.uid, parent_fo.uid, child_fo.uid]]

    parent_path = db.common.get_file_tree_path_for_uid_list([parent_fo.uid])
    assert parent_path == {parent_fo.uid: [[fw.uid, parent_fo.uid]]}

    combined = db.common.get_file_tree_path_for_uid_list([parent_fo.uid, child_fo.uid])
    assert len(combined) == 2


def test_get_vfps_for_uid_list(db):
    fw, parent_fo, child_fo = create_fw_with_parent_and_child()
    parent_fo.virtual_file_path = {fw.uid: ['/a/b']}
    child_fo.virtual_file_path = {parent_fo.uid: ['/test']}
    db.backend.insert_multiple_objects(fw, parent_fo, child_fo)
    expected = {
        parent_fo.uid: parent_fo.virtual_file_path,
        child_fo.uid: child_fo.virtual_file_path,
    }
    assert db.common.get_vfps_for_uid_list([parent_fo.uid, child_fo.uid]) == expected


def test_get_vfps_for_root_uid(db):
    fo, parent_1, fw_1, fw_2 = get_fo_with_2_root_fw()
    db.backend.insert_multiple_objects(fw_2, fw_1, parent_1, fo)

    assert db.common.get_vfps(fo.uid) == fo.virtual_file_path
    assert db.common.get_vfps_for_uid_list([fo.uid]) == {fo.uid: fo.virtual_file_path}

    assert db.common.get_vfps(fo.uid, root_uid=fw_1.uid) == {parent_1.uid: fo.virtual_file_path.get(parent_1.uid)}
    assert db.common.get_vfps(fo.uid, root_uid=fw_2.uid) == {fw_2.uid: fo.virtual_file_path.get(fw_2.uid)}
    assert db.common.get_vfps_for_uid_list([fo.uid], root_uid=fw_1.uid) == {
        fo.uid: {parent_1.uid: fo.virtual_file_path.get(parent_1.uid)}
    }


def test_get_vfps_in_parent(db):
    fo, fw = create_fw_with_child_fo()
    fo_2 = create_test_file_object(uid='fo_2')
    add_included_file(fo_2, fw, fw, ['/foo', '/bar'])
    db.backend.insert_multiple_objects(fw, fo, fo_2)
    result = db.common.get_vfps_in_parent(fw.uid)
    assert fo.uid in result and fo_2.uid in result
    assert result[fo.uid] == fo.virtual_file_path[fw.uid]
    assert set(result[fo_2.uid]) == set(fo_2.virtual_file_path[fw.uid])


def test_tree_path_with_root_uid(db):
    child_fo, parent_fo, fw, fw2 = get_fo_with_2_root_fw()
    db.backend.insert_multiple_objects(fw, fw2, parent_fo, child_fo)

    result = sorted(db.common.get_file_tree_path_for_uid_list([child_fo.uid], root_uid=None).get(child_fo.uid))
    assert len(result) == 2
    assert result[0] == [fw.uid, parent_fo.uid, child_fo.uid]
    assert result[1] == [fw2.uid, child_fo.uid]

    result = sorted(db.common.get_file_tree_path_for_uid_list([child_fo.uid], root_uid=fw.uid).get(child_fo.uid))
    assert len(result) == 1
    assert result[0][0] == fw.uid

    result = sorted(db.common.get_file_tree_path_for_uid_list([child_fo.uid], root_uid=fw2.uid).get(child_fo.uid))
    assert len(result) == 1
    assert result[0][0] == fw2.uid
