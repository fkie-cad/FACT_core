import pytest

from storage.db_interface_frontend import CachedQuery
from storage.query_conversion import QueryConversionException
from test.common_helper import (
    generate_analysis_entry,  # pylint: disable=wrong-import-order; pylint: disable=wrong-import-order
)
from test.common_helper import create_test_file_object, create_test_firmware
from web_interface.components.dependency_graph import DepGraphData
from web_interface.file_tree.file_tree_node import FileTreeNode

from .helper import (
    TEST_FO,
    TEST_FW,
    create_fw_with_child_fo,
    create_fw_with_parent_and_child,
    insert_test_fo,
    insert_test_fw,
)

DUMMY_RESULT = generate_analysis_entry(analysis_result={'key': 'result'})


def test_get_last_added_firmwares(db):
    insert_test_fw(db, 'fw1')
    insert_test_fw(db, 'fw2')
    insert_test_fw(db, 'fw3')
    fw4 = create_test_firmware()
    fw4.uid = 'fw4'
    fw4.processed_analysis['unpacker'] = {'plugin_used': 'foobar', 'plugin_version': '1', 'analysis_date': 0}
    db.backend.insert_object(fw4)

    result = db.frontend.get_last_added_firmwares(limit=3)
    assert len(result) == 3
    # fw4 was uploaded last and should be first in the list and so forth
    assert [fw.uid for fw in result] == ['fw4', 'fw3', 'fw2']
    assert 'foobar' in result[0].tags, 'unpacker tag should be set'


def test_get_hid(db):
    db.backend.add_object(TEST_FW)
    result = db.frontend.get_hid(TEST_FW.uid)
    assert result == 'test_vendor test_router - 0.1 (Router)', 'fw hid not correct'


def test_get_hid_fo(db):
    test_fo = create_test_file_object(bin_path='get_files_test/testfile2')
    test_fo.virtual_file_path = {'a': ['|a|/test_file'], 'b': ['|b|/get_files_test/testfile2']}
    db.backend.insert_object(test_fo)
    result = db.frontend.get_hid(test_fo.uid, root_uid='b')
    assert result == '/get_files_test/testfile2', 'fo hid not correct'
    result = db.frontend.get_hid(test_fo.uid)
    assert isinstance(result, str), 'result is not a string'
    assert result[0] == '/', 'first character not correct if no root_uid set'
    result = db.frontend.get_hid(test_fo.uid, root_uid='c')
    assert result[0] == '/', 'first character not correct if invalid root_uid set'


def test_get_hid_invalid_uid(db):
    result = db.frontend.get_hid('foo')
    assert result == '', 'invalid uid should result in empty string'


def test_get_data_for_nice_list(db):
    uid_list = [TEST_FW.uid, TEST_FO.uid]
    db.backend.add_object(TEST_FW)
    TEST_FO.virtual_file_path = {'TEST_FW.uid': [f'|{TEST_FW.uid}|/file/path']}
    db.backend.add_object(TEST_FO)

    nice_list_data = db.frontend.get_data_for_nice_list(uid_list, uid_list[0])
    assert len(nice_list_data) == 2
    expected_result = ['current_virtual_path', 'file_name', 'mime-type', 'size', 'uid']
    assert sorted(nice_list_data[0].keys()) == expected_result
    assert nice_list_data[0]['uid'] == TEST_FW.uid
    expected_hid = 'test_vendor test_router - 0.1 (Router)'
    assert nice_list_data[0]['current_virtual_path'][0] == expected_hid, 'UID should be replaced with HID'
    assert nice_list_data[1]['current_virtual_path'][0] == f'{expected_hid} | /file/path'


def test_get_device_class_list(db):
    insert_test_fw(db, 'fw1', device_class='class1')
    insert_test_fw(db, 'fw2', device_class='class2')
    insert_test_fw(db, 'fw3', device_class='class2')
    assert db.frontend.get_device_class_list() == ['class1', 'class2']


def test_get_vendor_list(db):
    insert_test_fw(db, 'fw1', vendor='vendor1')
    insert_test_fw(db, 'fw2', vendor='vendor2')
    insert_test_fw(db, 'fw3', vendor='vendor2')
    assert db.frontend.get_vendor_list() == ['vendor1', 'vendor2']


def test_get_device_name_dict(db):
    insert_test_fw(db, 'fw1', vendor='vendor1', device_class='class1', device_name='name1')
    insert_test_fw(db, 'fw2', vendor='vendor1', device_class='class1', device_name='name2')
    insert_test_fw(db, 'fw3', vendor='vendor1', device_class='class2', device_name='name1')
    insert_test_fw(db, 'fw4', vendor='vendor2', device_class='class1', device_name='name1')
    assert db.frontend.get_device_name_dict() == {
        'class1': {'vendor1': ['name1', 'name2'], 'vendor2': ['name1']},
        'class2': {'vendor1': ['name1']},
    }


def test_generic_search_fo(db):
    insert_test_fw(db, 'uid_1')
    result = db.frontend.generic_search({'file_name': 'test.zip'})
    assert result == ['uid_1']


def test_generic_search_date(db):
    insert_test_fw(db, 'uid_1', release_date='2022-02-22')
    assert db.frontend.generic_search({'release_date': '2022-02-22'}) == ['uid_1']
    assert db.frontend.generic_search({'release_date': {'$regex': '2022'}}) == ['uid_1']
    assert db.frontend.generic_search({'release_date': {'$regex': '2022-02'}}) == ['uid_1']
    assert db.frontend.generic_search({'release_date': {'$regex': '2020'}}) == []


def test_generic_search_regex(db):
    insert_test_fw(db, 'uid_1', file_name='some_file.zip')
    insert_test_fw(db, 'uid_2', file_name='other_file.zip')
    assert set(db.frontend.generic_search({'file_name': {'$regex': '[a-z]+.zip'}})) == {'uid_1', 'uid_2'}
    assert set(db.frontend.generic_search({'file_name': {'$regex': r'other.*\.zip'}})) == {'uid_2'}


def test_generic_search_like(db):
    insert_test_fw(db, 'uid_1', file_name='some_file.zip')
    insert_test_fw(db, 'uid_2', file_name='other_file.zip')
    assert set(db.frontend.generic_search({'file_name': {'$like': 'file.zip'}})) == {'uid_1', 'uid_2'}
    assert set(db.frontend.generic_search({'file_name': {'$like': 'me_FILE'}})) == {'uid_1'}, 'case should be ignored'


def test_generic_search_lt_gt(db):
    insert_test_fo(db, 'uid_1', size=10)
    insert_test_fo(db, 'uid_2', size=20)
    insert_test_fo(db, 'uid_3', size=30)
    assert set(db.frontend.generic_search({'size': {'$lt': 25}})) == {'uid_1', 'uid_2'}
    assert set(db.frontend.generic_search({'size': {'$gt': 15}})) == {'uid_2', 'uid_3'}


def test_generic_search_or(db):
    insert_test_fo(db, 'uid_1', file_name='some_file.zip', size=10)
    insert_test_fo(db, 'uid_2', file_name='other_file.zip', size=20)
    assert set(db.frontend.generic_search({'file_name': 'some_file.zip'})) == {'uid_1'}
    assert set(db.frontend.generic_search({'$or': {'file_name': 'some_file.zip'}})) == {'uid_1'}
    assert set(db.frontend.generic_search({'$or': {'file_name': 'some_file.zip', 'size': 20}})) == {'uid_1', 'uid_2'}
    assert set(db.frontend.generic_search({'$or': {'file_name': 'other_file.zip', 'size': {'$lt': 20}}})) == {
        'uid_1',
        'uid_2',
    }
    # "$or" query should still match if there is a firmware attribute in the query
    assert set(db.frontend.generic_search({'$or': {'file_name': 'some_file.zip', 'vendor': 'some_vendor'}})) == {
        'uid_1'
    }


def test_generic_search_unknown_op(db):
    with pytest.raises(QueryConversionException):
        db.frontend.generic_search({'file_name': {'$unknown': 'foo'}})


@pytest.mark.parametrize(
    'query, expected',
    [
        ({}, ['uid_1']),
        ({'vendor': 'test_vendor'}, ['uid_1']),
        ({'vendor': 'different_vendor'}, []),
    ],
)
def test_generic_search_fw(db, query, expected):
    insert_test_fw(db, 'uid_1', vendor='test_vendor')
    assert db.frontend.generic_search(query) == expected


def test_generic_search_parent(db):
    fo, fw = create_fw_with_child_fo()
    fw.file_name = 'fw.image'
    fo.file_name = 'foo.bar'
    fo.processed_analysis = {'plugin': generate_analysis_entry(analysis_result={'foo': 'bar', 'list': ['a', 'b']})}
    db.backend.insert_object(fw)
    db.backend.insert_object(fo)

    # insert some unrelated objects to assure non-matching objects are not found
    insert_test_fw(db, 'some_other_fw', vendor='foo123')
    fo2 = create_test_file_object()
    fo2.uid = 'some_other_fo'
    db.backend.insert_object(fo2)

    assert db.frontend.generic_search({'file_name': 'foo.bar'}) == [fo.uid]
    assert db.frontend.generic_search({'file_name': 'foo.bar'}, only_fo_parent_firmware=True) == [fw.uid]
    assert db.frontend.generic_search({'processed_analysis.plugin.foo': 'bar'}, only_fo_parent_firmware=True) == [
        fw.uid
    ]
    # root file objects of FW should also match:
    assert db.frontend.generic_search({'file_name': 'fw.image'}, only_fo_parent_firmware=True) == [fw.uid]
    assert db.frontend.generic_search({'vendor': 'foo123'}, only_fo_parent_firmware=True) == ['some_other_fw']


def test_generic_search_nested(db):
    fo, fw = create_fw_with_child_fo()
    fo.processed_analysis = {
        'plugin': generate_analysis_entry(
            analysis_result={'nested': {'key': 'value'}, 'nested_2': {'inner_nested': {'foo': 'bar', 'test': 3}}}
        )
    }
    db.backend.insert_object(fw)
    db.backend.insert_object(fo)

    assert db.frontend.generic_search({'processed_analysis.plugin.nested.key': 'value'}) == [fo.uid]
    assert db.frontend.generic_search({'processed_analysis.plugin.nested.key': {'$in': ['value', 'other_value']}}) == [
        fo.uid
    ]
    assert db.frontend.generic_search({'processed_analysis.plugin.nested_2.inner_nested.foo': 'bar'}) == [fo.uid]
    assert db.frontend.generic_search({'processed_analysis.plugin.nested_2.inner_nested.test': 3}) == [fo.uid]


def test_generic_search_json_array(db):
    fo, fw = create_fw_with_child_fo()
    fo.processed_analysis = {'plugin': generate_analysis_entry(analysis_result={'list': ['a', 'b']})}
    fw.processed_analysis = {'plugin': generate_analysis_entry(analysis_result={'list': ['b', 'c']})}
    db.backend.insert_object(fw)
    db.backend.insert_object(fo)

    assert db.frontend.generic_search({'processed_analysis.plugin.list': {'$contains': 'a'}}) == [fo.uid]
    assert db.frontend.generic_search({'processed_analysis.plugin.list': {'$contains': ['a']}}) == [fo.uid]
    assert set(db.frontend.generic_search({'processed_analysis.plugin.list': {'$contains': 'b'}})) == {fo.uid, fw.uid}
    assert db.frontend.generic_search({'processed_analysis.plugin.list': {'$contains': 'd'}}) == []


def test_generic_search_json_types(db):
    fo, fw = create_fw_with_child_fo()
    fo.processed_analysis = {
        'plugin': generate_analysis_entry(analysis_result={'str': 'a', 'int': 1, 'float': 1.23, 'bool': True})
    }
    db.backend.insert_object(fw)
    db.backend.insert_object(fo)

    assert db.frontend.generic_search({'processed_analysis.plugin.str': 'a'}) == [fo.uid]
    assert db.frontend.generic_search({'processed_analysis.plugin.int': 1}) == [fo.uid]
    assert db.frontend.generic_search({'processed_analysis.plugin.float': 1.23}) == [fo.uid]
    assert db.frontend.generic_search({'processed_analysis.plugin.bool': True}) == [fo.uid]


def test_generic_search_json_like(db):
    fo, fw = create_fw_with_child_fo()
    fo.processed_analysis = {'plugin': generate_analysis_entry(analysis_result={'foo': 'bar123'})}
    db.backend.insert_object(fw)
    db.backend.insert_object(fo)

    assert db.frontend.generic_search({'processed_analysis.plugin.foo': 'bar123'}) == [fo.uid]
    assert db.frontend.generic_search({'processed_analysis.plugin.foo': {'$like': 'ar12'}}) == [fo.uid]
    assert db.frontend.generic_search({'processed_analysis.plugin.foo': {'$like': 'no-match'}}) == []


def test_generic_search_wrong_key(db):
    fo, fw = create_fw_with_child_fo()
    fo.processed_analysis = {'plugin': generate_analysis_entry(analysis_result={'nested': {'key': 'value'}})}
    db.backend.insert_object(fw)
    db.backend.insert_object(fo)

    assert db.frontend.generic_search({'processed_analysis.plugin.unknown': 'value'}) == []
    assert db.frontend.generic_search({'processed_analysis.plugin.nested.unknown': 'value'}) == []
    assert db.frontend.generic_search({'processed_analysis.plugin.nested.key.too_deep': 'value'}) == []


def test_generic_search_summary(db):
    fo, fw = create_fw_with_child_fo()
    fo.processed_analysis = {'plugin': generate_analysis_entry(summary=['foo', 'bar', 'test 123'])}
    db.backend.insert_object(fw)
    db.backend.insert_object(fo)

    assert db.frontend.generic_search({'processed_analysis.plugin.summary': 'foo'}) == [fo.uid]
    assert db.frontend.generic_search({'processed_analysis.plugin.summary': {'$regex': 'test'}}) == [fo.uid]
    assert db.frontend.generic_search({'processed_analysis.plugin.summary': ['foo']}) == [fo.uid]

    with pytest.raises(QueryConversionException):
        db.frontend.generic_search({'processed_analysis.plugin.summary': {'$foo': 'bar'}})


def test_generic_search_tags(db):
    insert_test_fw(db, uid='fw_1', tags={'foo': 'some_color', 'bar': 'some_color'})
    insert_test_fw(db, uid='fw_2', tags={'foo': 'some_color', 'test': 'some_color'})

    assert db.frontend.generic_search({'firmware_tags': 'bar'}) == ['fw_1']
    assert db.frontend.generic_search({'firmware_tags': 'test'}) == ['fw_2']
    assert sorted(db.frontend.generic_search({'firmware_tags': 'foo'})) == ['fw_1', 'fw_2']
    assert sorted(db.frontend.generic_search({'firmware_tags': {'$contains': 'foo'}})) == ['fw_1', 'fw_2']
    assert sorted(db.frontend.generic_search({'firmware_tags': {'$overlap': ['bar', 'test']}})) == ['fw_1', 'fw_2']
    assert db.frontend.generic_search({'firmware_tags': {'$overlap': ['none']}}) == []


def test_inverted_search(db):
    fo, fw = create_fw_with_child_fo()
    fo.file_name = 'foo.bar'
    db.backend.insert_object(fw)
    db.backend.insert_object(fo)
    insert_test_fw(db, 'some_other_fw')

    assert db.frontend.generic_search({'file_name': 'foo.bar'}, only_fo_parent_firmware=True) == [fw.uid]
    assert db.frontend.generic_search({'file_name': 'foo.bar'}, only_fo_parent_firmware=True, inverted=True) == [
        'some_other_fw'
    ]


def test_search_limit_skip_and_order(db):
    insert_test_fw(db, 'uid_1', device_class='foo', vendor='v1', device_name='n2', file_name='f1')
    insert_test_fw(db, 'uid_2', device_class='foo', vendor='v1', device_name='n3', file_name='f2')
    insert_test_fw(db, 'uid_3', device_class='foo', vendor='v1', device_name='n1', file_name='f3')
    insert_test_fw(db, 'uid_4', device_class='foo', vendor='v2', device_name='n1', file_name='f4')

    expected_result_fw = ['uid_3', 'uid_1', 'uid_2', 'uid_4']
    result = db.frontend.generic_search({})
    assert result == expected_result_fw, 'sorted wrongly (FW sort key should be vendor > device)'
    result = db.frontend.generic_search({'device_class': 'foo'}, only_fo_parent_firmware=True)
    assert result == expected_result_fw, 'sorted wrongly (FW sort key should be vendor > device)'

    expected_result_fo = ['uid_1', 'uid_2', 'uid_3', 'uid_4']
    result = db.frontend.generic_search({'device_class': 'foo'})
    assert result == expected_result_fo, 'sorted wrongly (FO sort key should be file name)'
    result = db.frontend.generic_search({'device_class': 'foo'}, limit=2)
    assert result == expected_result_fo[:2], 'limit does not work correctly'
    result = db.frontend.generic_search({'device_class': 'foo'}, limit=2, skip=2)
    assert result == expected_result_fo[2:], 'skip does not work correctly'


def test_search_analysis_result(db):
    insert_test_fw(db, 'uid_1')
    insert_test_fw(db, 'uid_2')
    db.backend.add_analysis('uid_2', 'test_plugin', generate_analysis_entry(analysis_result={'foo': 'bar', 'test': 3}))
    assert db.frontend.generic_search({'processed_analysis.test_plugin.foo': 'bar'}) == ['uid_2']
    assert db.frontend.generic_search({'processed_analysis.test_plugin.test': 3}) == ['uid_2']


def test_get_other_versions(db):
    insert_test_fw(db, 'uid_1', version='1.0')
    insert_test_fw(db, 'uid_2', version='2.0')
    insert_test_fw(db, 'uid_3', version='3.0')
    fw1 = db.frontend.get_object('uid_1')
    result = db.frontend.get_other_versions_of_firmware(fw1)
    assert result == [('uid_2', '2.0'), ('uid_3', '3.0')]

    assert db.frontend.get_other_versions_of_firmware(TEST_FO) == []


def test_get_latest_comments(db):
    fo1 = create_test_file_object()
    fo1.comments = [
        {'author': 'anonymous', 'comment': 'comment1', 'time': '1'},
        {'author': 'anonymous', 'comment': 'comment3', 'time': '3'},
    ]
    db.backend.insert_object(fo1)
    fo2 = create_test_file_object()
    fo2.uid = 'fo2_uid'
    fo2.comments = [{'author': 'foo', 'comment': 'comment2', 'time': '2'}]
    db.backend.insert_object(fo2)
    result = db.frontend.get_latest_comments(limit=2)
    assert len(result) == 2
    assert result[0]['time'] == '3', 'the first entry should have the newest timestamp'
    assert result[1]['time'] == '2'
    assert result[1]['comment'] == 'comment2'


def test_generate_file_tree_level(db):
    child_fo, parent_fw = create_fw_with_child_fo()
    child_fo.processed_analysis['file_type'] = generate_analysis_entry(analysis_result={'mime': 'sometype'})
    uid = parent_fw.uid
    child_fo.virtual_file_path = {uid: [f'|{uid}|/folder/{child_fo.file_name}']}
    db.backend.add_object(parent_fw)
    db.backend.add_object(child_fo)
    for node in db.frontend.generate_file_tree_level(uid, uid):
        assert isinstance(node, FileTreeNode)
        assert node.name == parent_fw.file_name
        assert node.has_children
    for node in db.frontend.generate_file_tree_level(child_fo.uid, uid):
        assert isinstance(node, FileTreeNode)
        assert node.name == 'folder'
        assert node.has_children
        virtual_grand_child = node.get_list_of_child_nodes()[0]
        assert virtual_grand_child.type == 'sometype'
        assert not virtual_grand_child.has_children
        assert virtual_grand_child.name == child_fo.file_name


def test_get_file_tree_data(db):
    fw, parent_fo, child_fo = create_fw_with_parent_and_child()
    fw.processed_analysis = {'file_type': generate_analysis_entry(analysis_result={'failed': 'some error'})}
    parent_fo.processed_analysis = {'file_type': generate_analysis_entry(analysis_result={'mime': 'foo_type'})}
    child_fo.processed_analysis = {}  # simulate that file_type did not run yet
    db.backend.add_object(fw)
    db.backend.add_object(parent_fo)
    db.backend.add_object(child_fo)

    result = db.frontend.get_file_tree_data([fw.uid, parent_fo.uid, child_fo.uid])
    assert len(result) == 3
    result_by_uid = {r.uid: r for r in result}
    assert result_by_uid[parent_fo.uid].uid == parent_fo.uid
    assert result_by_uid[parent_fo.uid].file_name == parent_fo.file_name
    assert result_by_uid[parent_fo.uid].size == parent_fo.size
    assert result_by_uid[parent_fo.uid].virtual_file_path == parent_fo.virtual_file_path
    assert result_by_uid[fw.uid].mime is None
    assert result_by_uid[parent_fo.uid].mime == 'foo_type'
    assert result_by_uid[child_fo.uid].mime is None
    assert result_by_uid[fw.uid].included_files == [parent_fo.uid]
    assert result_by_uid[parent_fo.uid].included_files == [child_fo.uid]


@pytest.mark.parametrize(
    'query, expected, expected_fw, expected_inv',
    [
        ({}, 1, 1, 1),
        ({'size': 123}, 2, 1, 0),
        ({'file_name': 'foo.bar'}, 1, 1, 0),
        ({'vendor': 'test_vendor'}, 1, 1, 0),
    ],
)
def test_get_number_of_total_matches(db, query, expected, expected_fw, expected_inv):
    fw, parent_fo, child_fo = create_fw_with_parent_and_child()
    fw.vendor = 'test_vendor'
    parent_fo.size = 123
    child_fo.size = 123
    child_fo.file_name = 'foo.bar'
    db.backend.add_object(fw)
    db.backend.add_object(parent_fo)
    db.backend.add_object(child_fo)
    assert db.frontend.get_number_of_total_matches(query, only_parent_firmwares=False, inverted=False) == expected
    assert db.frontend.get_number_of_total_matches(query, only_parent_firmwares=True, inverted=False) == expected_fw
    assert db.frontend.get_number_of_total_matches(query, only_parent_firmwares=True, inverted=True) == expected_inv


def test_rest_get_file_object_uids(db):
    insert_test_fo(db, 'fo1', 'file_name_1', size=10)
    insert_test_fo(db, 'fo2', size=10)
    insert_test_fo(db, 'fo3', size=11)

    assert sorted(db.frontend.rest_get_file_object_uids(offset=None, limit=None)) == ['fo1', 'fo2', 'fo3']
    assert db.frontend.rest_get_file_object_uids(offset=1, limit=1) == ['fo2']
    assert db.frontend.rest_get_file_object_uids(offset=None, limit=None, query={'file_name': 'file_name_1'}) == ['fo1']
    assert db.frontend.rest_get_file_object_uids(offset=None, limit=None, query={'file_name': 'non-existent'}) == []
    assert sorted(db.frontend.rest_get_file_object_uids(offset=None, limit=None, query={'size': 10})) == ['fo1', 'fo2']


def test_rest_get_firmware_uids(db):
    child_fo, parent_fw = create_fw_with_child_fo()
    child_fo.file_name = 'foo_file'
    db.backend.add_object(parent_fw)
    db.backend.add_object(child_fo)
    test_fw1 = insert_test_fw(db, 'fw1', vendor='foo_vendor', file_name='fw1', device_name='some_device')
    test_fw2 = insert_test_fw(db, 'fw2', vendor='foo_vendor', file_name='fw2')

    assert sorted(db.frontend.rest_get_firmware_uids(offset=None, limit=None)) == [
        parent_fw.uid,
        test_fw1.uid,
        test_fw2.uid,
    ]
    assert sorted(db.frontend.rest_get_firmware_uids(query={}, offset=0, limit=0)) == [
        parent_fw.uid,
        test_fw1.uid,
        test_fw2.uid,
    ]
    assert db.frontend.rest_get_firmware_uids(offset=1, limit=1) == [test_fw1.uid]
    assert sorted(db.frontend.rest_get_firmware_uids(offset=None, limit=None, query={'vendor': 'foo_vendor'})) == [
        test_fw1.uid,
        test_fw2.uid,
    ]
    assert sorted(
        db.frontend.rest_get_firmware_uids(offset=None, limit=None, query={'device_name': 'some_device'})
    ) == [test_fw1.uid]
    assert sorted(
        db.frontend.rest_get_firmware_uids(offset=None, limit=None, query={'file_name': parent_fw.file_name})
    ) == [parent_fw.uid]
    assert sorted(
        db.frontend.rest_get_firmware_uids(
            offset=None, limit=None, query={'file_name': child_fo.file_name}, recursive=True
        )
    ) == [parent_fw.uid]
    assert sorted(
        db.frontend.rest_get_firmware_uids(
            offset=None, limit=None, query={'file_name': child_fo.file_name}, recursive=True, inverted=True
        )
    ) == [test_fw1.uid, test_fw2.uid]


def test_find_missing_analyses(db):
    fw, parent_fo, child_fo = create_fw_with_parent_and_child()
    fw.processed_analysis = {'plugin1': DUMMY_RESULT, 'plugin2': DUMMY_RESULT, 'plugin3': DUMMY_RESULT}
    parent_fo.processed_analysis = {'plugin1': DUMMY_RESULT, 'plugin2': DUMMY_RESULT}
    child_fo.processed_analysis = {'plugin1': DUMMY_RESULT}
    db.backend.insert_object(fw)
    db.backend.insert_object(parent_fo)
    db.backend.insert_object(child_fo)

    assert db.frontend.find_missing_analyses() == {fw.uid: {parent_fo.uid, child_fo.uid}}


def test_find_failed_analyses(db):
    failed_result = generate_analysis_entry(analysis_result={'failed': 'it failed'})
    insert_test_fo(db, 'fo1', analysis={'plugin1': DUMMY_RESULT, 'plugin2': failed_result})
    insert_test_fo(db, 'fo2', analysis={'plugin1': failed_result, 'plugin2': failed_result})

    assert db.frontend.find_failed_analyses() == {'plugin1': {'fo2'}, 'plugin2': {'fo1', 'fo2'}}


def test_get_tag_list(db):
    assert db.frontend.get_tag_list() == []

    insert_test_fw(db, uid='fw_1', tags={'foo': 'some_color', 'bar': 'some_color'})
    insert_test_fw(db, uid='fw_2', tags={'foo': 'some_color', 'test': 'some_color'})

    assert db.frontend.get_tag_list() == ['bar', 'foo', 'test']


# --- search cache ---


def test_get_query_from_cache(db):
    assert db.frontend.get_query_from_cache('non-existent') is None

    id_ = db.frontend_ed.add_to_search_query_cache('foo', 'bar')
    entry = db.frontend.get_query_from_cache(id_)
    assert isinstance(entry, CachedQuery)
    assert entry.query == 'foo'
    assert entry.yara_rule == 'bar'


def test_get_cached_count(db):
    assert db.frontend.get_total_cached_query_count() == 0

    db.frontend_ed.add_to_search_query_cache('foo', 'bar')
    assert db.frontend.get_total_cached_query_count() == 1

    db.frontend_ed.add_to_search_query_cache('bar', 'foo')
    assert db.frontend.get_total_cached_query_count() == 2


def test_search_query_cache(db):
    assert db.frontend.search_query_cache(offset=0, limit=10) == []

    id1 = db.frontend_ed.add_to_search_query_cache('foo', 'rule bar{}')
    id2 = db.frontend_ed.add_to_search_query_cache('bar', 'rule foo{}')
    assert sorted(db.frontend.search_query_cache(offset=0, limit=10)) == [
        (id1, 'rule bar{}', ['bar']),
        (id2, 'rule foo{}', ['foo']),
    ]


def test_data_for_dependency_graph(db):
    child_fo, parent_fw = create_fw_with_child_fo()
    assert db.frontend.get_data_for_dependency_graph(parent_fw.uid) == []

    db.backend.insert_object(parent_fw)
    db.backend.insert_object(child_fo)

    assert db.frontend.get_data_for_dependency_graph(child_fo.uid) == [], 'should be empty if no files included'

    result = db.frontend.get_data_for_dependency_graph(parent_fw.uid)
    assert len(result) == 1
    assert isinstance(result[0], DepGraphData)
    assert result[0].uid == child_fo.uid
    assert result[0].libraries is None
    assert result[0].full_type == 'Not a PE file'
    assert result[0].file_name == 'testfile1'
