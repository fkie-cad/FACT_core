import pytest

from storage.db_interface_frontend import CachedQuery
from storage.query_conversion import QueryConversionException
from test.common_helper import create_test_file_object, create_test_firmware, generate_analysis_entry
from web_interface.components.dependency_graph import DepGraphData
from web_interface.file_tree.file_tree_node import FileTreeNode

from .helper import (
    TEST_FO,
    TEST_FW,
    create_fw_with_child_fo,
    create_fw_with_parent_and_child,
    get_fo_with_2_root_fw,
    insert_test_fo,
    insert_test_fw,
)

DUMMY_RESULT = generate_analysis_entry(analysis_result={'key': 'result'})


def test_get_last_added_firmwares(frontend_db, backend_db):
    insert_test_fw(backend_db, 'fw1')
    insert_test_fw(backend_db, 'fw2')
    insert_test_fw(backend_db, 'fw3')
    fw4 = create_test_firmware()
    fw4.uid = 'fw4'
    fw4.processed_analysis['unpacker'] = {
        'result': {'plugin_used': 'foobar'},
        'plugin_version': '1',
        'analysis_date': 0,
    }
    backend_db.insert_object(fw4)

    result = frontend_db.get_last_added_firmwares(limit=3)
    assert len(result) == 3  # noqa: PLR2004
    # fw4 was uploaded last and should be first in the list and so forth
    assert [fw.uid for fw in result] == ['fw4', 'fw3', 'fw2']
    assert 'foobar' in result[0].tags, 'unpacker tag should be set'


def test_get_hid(frontend_db, backend_db):
    backend_db.add_object(TEST_FW)
    result = frontend_db.get_hid(TEST_FW.uid)
    assert result == 'test_vendor test_router - 0.1 (Router)', 'fw hid not correct'


def test_get_hid_fo(frontend_db, backend_db):
    fo, parent_1, fw_1, fw_2 = get_fo_with_2_root_fw()
    fo.virtual_file_path = {parent_1.uid: ['/test_file'], fw_2.uid: ['/get_files_test/testfile2']}
    backend_db.insert_multiple_objects(fw_2, fw_1, parent_1, fo)
    result = frontend_db.get_hid(fo.uid, root_uid=fw_2.uid)
    assert result == '/get_files_test/testfile2', 'fo hid not correct'
    result = frontend_db.get_hid(fo.uid)
    assert isinstance(result, str), 'result is not a string'
    assert result.startswith('/'), 'first character not correct if no root_uid set'
    result = frontend_db.get_hid(fo.uid, root_uid='invalid')
    assert result == fo.file_name, 'file name should be fallback'


def test_get_hid_invalid_uid(frontend_db):
    result = frontend_db.get_hid('foo')
    assert result == '', 'invalid uid should result in empty string'


def test_get_hid_dict(frontend_db, backend_db):
    fo, fw = create_fw_with_child_fo()
    fo.virtual_file_path[fw.uid] = ['/foo']
    backend_db.insert_multiple_objects(fw, fo)
    uid_set = {fo.uid, fw.uid}
    hid_dict = frontend_db.get_hid_dict(uid_set, root_uid=fw.uid)
    assert all(uid in hid_dict for uid in uid_set)
    assert hid_dict[fo.uid] == '/foo'
    assert all(element in hid_dict[fw.uid] for element in [fw.vendor, fw.device_class, fw.device_name, fw.version])


def test_get_data_for_nice_list(frontend_db, backend_db):
    fo, fw = create_fw_with_child_fo()
    uid_list = [fw.uid, fo.uid]
    fo.virtual_file_path = {fw.uid: ['/file/path']}
    backend_db.insert_multiple_objects(fw, fo)

    nice_list_data = frontend_db.get_data_for_nice_list(uid_list, uid_list[0])
    assert len(nice_list_data) == 2  # noqa: PLR2004
    expected_result = ['current_virtual_path', 'file_name', 'mime-type', 'size', 'uid']
    assert sorted(nice_list_data[0].keys()) == expected_result
    assert nice_list_data[0]['uid'] == TEST_FW.uid
    expected_hid = 'test_vendor test_router - 0.1 (Router)'
    assert nice_list_data[0]['current_virtual_path'][0] == expected_hid, 'UID should be replaced with HID'
    assert nice_list_data[1]['current_virtual_path'][0] == f'{expected_hid} | /file/path'


def test_get_device_class_list(frontend_db, backend_db):
    insert_test_fw(backend_db, 'fw1', device_class='class1')
    insert_test_fw(backend_db, 'fw2', device_class='class2')
    insert_test_fw(backend_db, 'fw3', device_class='class2')
    assert frontend_db.get_device_class_list() == ['class1', 'class2']


def test_get_vendor_list(frontend_db, backend_db):
    insert_test_fw(backend_db, 'fw1', vendor='vendor1')
    insert_test_fw(backend_db, 'fw2', vendor='vendor2')
    insert_test_fw(backend_db, 'fw3', vendor='vendor2')
    assert frontend_db.get_vendor_list() == ['vendor1', 'vendor2']


def test_get_device_name_dict(backend_db, frontend_db):
    insert_test_fw(backend_db, 'fw1', vendor='vendor1', device_class='class1', device_name='name1')
    insert_test_fw(backend_db, 'fw2', vendor='vendor1', device_class='class1', device_name='name2')
    insert_test_fw(backend_db, 'fw3', vendor='vendor1', device_class='class2', device_name='name1')
    insert_test_fw(backend_db, 'fw4', vendor='vendor2', device_class='class1', device_name='name1')
    device_name_dict = frontend_db.get_device_name_dict()
    device_name_dict.get('class1', {}).get('vendor1', []).sort()
    assert device_name_dict == {
        'class1': {'vendor1': ['name1', 'name2'], 'vendor2': ['name1']},
        'class2': {'vendor1': ['name1']},
    }


def test_generic_search_fo(frontend_db, backend_db):
    insert_test_fw(backend_db, 'uid_1')
    result = frontend_db.generic_search({'file_name': 'test.zip'})
    assert result == ['uid_1']


def test_generic_search_date(frontend_db, backend_db):
    insert_test_fw(backend_db, 'uid_1', release_date='2022-02-22')
    assert frontend_db.generic_search({'release_date': '2022-02-22'}) == ['uid_1']
    assert frontend_db.generic_search({'release_date': {'$regex': '2022'}}) == ['uid_1']
    assert frontend_db.generic_search({'release_date': {'$regex': '2022-02'}}) == ['uid_1']
    assert frontend_db.generic_search({'release_date': {'$regex': '2020'}}) == []


def test_generic_search_regex(frontend_db, backend_db):
    insert_test_fw(backend_db, 'uid_1', file_name='some_file.zip')
    insert_test_fw(backend_db, 'uid_2', file_name='other_file.zip')
    assert set(frontend_db.generic_search({'file_name': {'$regex': '[a-z]+.zip'}})) == {'uid_1', 'uid_2'}
    assert set(frontend_db.generic_search({'file_name': {'$regex': r'other.*\.zip'}})) == {'uid_2'}


def test_generic_search_like(frontend_db, backend_db):
    insert_test_fw(backend_db, 'uid_1', file_name='some_file.zip')
    insert_test_fw(backend_db, 'uid_2', file_name='other_file.zip')
    assert set(frontend_db.generic_search({'file_name': {'$like': 'file.zip'}})) == {'uid_1', 'uid_2'}
    assert set(frontend_db.generic_search({'file_name': {'$like': 'me_FILE'}})) == {'uid_1'}, 'case should be ignored'


def test_generic_search_lt_gt(frontend_db, backend_db):
    insert_test_fo(backend_db, 'uid_1', size=10)
    insert_test_fo(backend_db, 'uid_2', size=20)
    insert_test_fo(backend_db, 'uid_3', size=30)
    assert set(frontend_db.generic_search({'size': {'$lt': 25}})) == {'uid_1', 'uid_2'}
    assert set(frontend_db.generic_search({'size': {'$gt': 15}})) == {'uid_2', 'uid_3'}


def test_generic_search_or(frontend_db, backend_db):
    insert_test_fo(backend_db, 'uid_1', file_name='some_file.zip', size=10)
    insert_test_fo(backend_db, 'uid_2', file_name='other_file.zip', size=20)
    assert set(frontend_db.generic_search({'file_name': 'some_file.zip'})) == {'uid_1'}
    assert set(frontend_db.generic_search({'$or': {'file_name': 'some_file.zip'}})) == {'uid_1'}
    assert set(frontend_db.generic_search({'$or': {'file_name': 'some_file.zip', 'size': 20}})) == {'uid_1', 'uid_2'}
    assert set(frontend_db.generic_search({'$or': {'file_name': 'other_file.zip', 'size': {'$lt': 20}}})) == {
        'uid_1',
        'uid_2',
    }
    # "$or" query should still match if there is a firmware attribute in the query
    assert set(frontend_db.generic_search({'$or': {'file_name': 'some_file.zip', 'vendor': 'some_vendor'}})) == {
        'uid_1'
    }


def test_generic_search_unknown_op(frontend_db):
    with pytest.raises(QueryConversionException):
        frontend_db.generic_search({'file_name': {'$unknown': 'foo'}})


@pytest.mark.parametrize(
    ('query', 'expected'),
    [
        ({}, ['uid_1']),
        ({'vendor': 'test_vendor'}, ['uid_1']),
        ({'vendor': 'different_vendor'}, []),
    ],
)
def test_generic_search_fw(frontend_db, backend_db, query, expected):
    insert_test_fw(backend_db, 'uid_1', vendor='test_vendor')
    assert frontend_db.generic_search(query) == expected


def test_generic_search_parent(frontend_db, backend_db):
    fo, fw = create_fw_with_child_fo()
    fw.file_name = 'fw.image'
    fo.file_name = 'foo.bar'
    fo.processed_analysis = {'plugin': generate_analysis_entry(analysis_result={'foo': 'bar', 'list': ['a', 'b']})}
    backend_db.insert_multiple_objects(fw, fo)

    # insert some unrelated objects to assure non-matching objects are not found
    insert_test_fw(backend_db, 'some_other_fw', vendor='foo123')
    fo2 = create_test_file_object()
    fo2.uid = 'some_other_fo'
    backend_db.insert_object(fo2)

    assert frontend_db.generic_search({'file_name': 'foo.bar'}) == [fo.uid]
    assert frontend_db.generic_search({'file_name': 'foo.bar'}, only_fo_parent_firmware=True) == [fw.uid]
    assert frontend_db.generic_search({'processed_analysis.plugin.foo': 'bar'}, only_fo_parent_firmware=True) == [
        fw.uid
    ]
    # root file objects of FW should also match:
    assert frontend_db.generic_search({'file_name': 'fw.image'}, only_fo_parent_firmware=True) == [fw.uid]
    assert frontend_db.generic_search({'vendor': 'foo123'}, only_fo_parent_firmware=True) == ['some_other_fw']


def test_generic_search_nested(frontend_db, backend_db):
    fo, fw = create_fw_with_child_fo()
    fo.processed_analysis = {
        'plugin': generate_analysis_entry(
            analysis_result={'nested': {'key': 'value'}, 'nested_2': {'inner_nested': {'foo': 'bar', 'test': 3}}}
        )
    }
    backend_db.insert_multiple_objects(fw, fo)

    assert frontend_db.generic_search({'processed_analysis.plugin.nested.key': 'value'}) == [fo.uid]
    assert frontend_db.generic_search({'processed_analysis.plugin.nested.key': {'$in': ['value', 'other_value']}}) == [
        fo.uid
    ]
    assert frontend_db.generic_search({'processed_analysis.plugin.nested_2.inner_nested.foo': 'bar'}) == [fo.uid]
    assert frontend_db.generic_search({'processed_analysis.plugin.nested_2.inner_nested.test': 3}) == [fo.uid]


def test_generic_search_json_array(frontend_db, backend_db):
    fo, fw = create_fw_with_child_fo()
    fo.processed_analysis = {'plugin': generate_analysis_entry(analysis_result={'list': ['a', 'b']})}
    fw.processed_analysis = {'plugin': generate_analysis_entry(analysis_result={'list': ['b', 'c']})}
    backend_db.insert_object(fw)
    backend_db.insert_object(fo)

    assert frontend_db.generic_search({'processed_analysis.plugin.list': {'$contains': 'a'}}) == [fo.uid]
    assert frontend_db.generic_search({'processed_analysis.plugin.list': {'$contains': ['a']}}) == [fo.uid]
    assert set(frontend_db.generic_search({'processed_analysis.plugin.list': {'$contains': 'b'}})) == {fo.uid, fw.uid}
    assert frontend_db.generic_search({'processed_analysis.plugin.list': {'$contains': 'd'}}) == []


def test_generic_search_dict_in_list(backend_db, frontend_db):
    fw, parent_fo, child_fo = create_fw_with_parent_and_child()
    parent_fo.processed_analysis = {
        'plugin': generate_analysis_entry(analysis_result={'key': [{'name': 'a', 'foo': 'bar'}]})
    }
    child_fo.processed_analysis = {
        'plugin': generate_analysis_entry(
            analysis_result={'key': [{'name': 'b', 'foo': 'bar'}, {'name': 'c', 'foo': 'test'}]}
        )
    }
    backend_db.insert_object(fw)
    backend_db.insert_object(parent_fo)
    backend_db.insert_object(child_fo)

    assert frontend_db.generic_search({'processed_analysis.plugin.key': {'$contains': [{'name': 'a'}]}}) == [
        parent_fo.uid
    ]
    assert frontend_db.generic_search({'processed_analysis.plugin.key': {'$contains': [{'name': 'b'}]}}) == [
        child_fo.uid
    ]
    assert set(frontend_db.generic_search({'processed_analysis.plugin.key': {'$contains': [{'foo': 'bar'}]}})) == {
        parent_fo.uid,
        child_fo.uid,
    }


def test_generic_search_json_types(frontend_db, backend_db):
    fo, fw = create_fw_with_child_fo()
    fo.processed_analysis = {
        'plugin': generate_analysis_entry(analysis_result={'str': 'a', 'int': 1, 'float': 1.23, 'bool': True})
    }
    backend_db.insert_object(fw)
    backend_db.insert_object(fo)

    assert frontend_db.generic_search({'processed_analysis.plugin.str': 'a'}) == [fo.uid]
    assert frontend_db.generic_search({'processed_analysis.plugin.int': 1}) == [fo.uid]
    assert frontend_db.generic_search({'processed_analysis.plugin.float': 1.23}) == [fo.uid]
    assert frontend_db.generic_search({'processed_analysis.plugin.bool': True}) == [fo.uid]


def test_generic_search_json_like(frontend_db, backend_db):
    fo, fw = create_fw_with_child_fo()
    fo.processed_analysis = {'plugin': generate_analysis_entry(analysis_result={'foo': 'bar123'})}
    backend_db.insert_object(fw)
    backend_db.insert_object(fo)

    assert frontend_db.generic_search({'processed_analysis.plugin.foo': 'bar123'}) == [fo.uid]
    assert frontend_db.generic_search({'processed_analysis.plugin.foo': {'$like': 'ar12'}}) == [fo.uid]
    assert frontend_db.generic_search({'processed_analysis.plugin.foo': {'$like': 'no-match'}}) == []


def test_generic_search_wrong_key(frontend_db, backend_db):
    fo, fw = create_fw_with_child_fo()
    fo.processed_analysis = {'plugin': generate_analysis_entry(analysis_result={'nested': {'key': 'value'}})}
    backend_db.insert_object(fw)
    backend_db.insert_object(fo)

    assert frontend_db.generic_search({'processed_analysis.plugin.unknown': 'value'}) == []
    assert frontend_db.generic_search({'processed_analysis.plugin.nested.unknown': 'value'}) == []
    assert frontend_db.generic_search({'processed_analysis.plugin.nested.key.too_deep': 'value'}) == []


def test_generic_search_summary(frontend_db, backend_db):
    fo, fw = create_fw_with_child_fo()
    fo.processed_analysis = {'plugin': generate_analysis_entry(summary=['foo', 'bar', 'test 123'])}
    backend_db.insert_object(fw)
    backend_db.insert_object(fo)

    assert frontend_db.generic_search({'processed_analysis.plugin.summary': 'foo'}) == [fo.uid]
    assert frontend_db.generic_search({'processed_analysis.plugin.summary': {'$regex': 'test'}}) == [fo.uid]
    assert frontend_db.generic_search({'processed_analysis.plugin.summary': ['foo']}) == [fo.uid]

    with pytest.raises(QueryConversionException):
        frontend_db.generic_search({'processed_analysis.plugin.summary': {'$foo': 'bar'}})


def test_generic_search_tags(frontend_db, backend_db):
    insert_test_fw(backend_db, uid='fw_1', tags={'foo': 'some_color', 'bar': 'some_color'})
    insert_test_fw(backend_db, uid='fw_2', tags={'foo': 'some_color', 'test': 'some_color'})

    assert frontend_db.generic_search({'firmware_tags': 'bar'}) == ['fw_1']
    assert frontend_db.generic_search({'firmware_tags': 'test'}) == ['fw_2']
    assert sorted(frontend_db.generic_search({'firmware_tags': 'foo'})) == ['fw_1', 'fw_2']
    assert sorted(frontend_db.generic_search({'firmware_tags': {'$contains': 'foo'}})) == ['fw_1', 'fw_2']
    assert sorted(frontend_db.generic_search({'firmware_tags': {'$overlap': ['bar', 'test']}})) == ['fw_1', 'fw_2']
    assert frontend_db.generic_search({'firmware_tags': {'$overlap': ['none']}}) == []


def test_generic_search_unequal(backend_db, frontend_db):
    insert_test_fw(backend_db, 'uid1', device_class='c1', vendor='v1', device_name='n1', file_name='f1')
    insert_test_fw(backend_db, 'uid2', device_class='c2', vendor='v2', device_name='n2', file_name='f2')
    backend_db.add_analysis('uid1', 'some_plugin', generate_analysis_entry(analysis_result={'foo': 'foo', 'test': 1}))
    backend_db.add_analysis('uid2', 'some_plugin', generate_analysis_entry(analysis_result={'foo': 'bar', 'test': 2}))

    assert frontend_db.generic_search({'device_class': {'$ne': 'c1'}}) == ['uid2']
    assert frontend_db.generic_search({'vendor': {'$ne': 'v2'}}) == ['uid1']
    assert frontend_db.generic_search({'vendor': {'$ne': 'v2'}}) == ['uid1']
    assert frontend_db.generic_search({'processed_analysis.some_plugin.foo': {'$ne': 'bar'}}) == ['uid1']
    assert frontend_db.generic_search({'processed_analysis.some_plugin.test': {'$ne': 2}}) == ['uid1']


def test_inverted_search(backend_db, frontend_db):
    fo, fw = create_fw_with_child_fo()
    fo.file_name = 'foo.bar'
    backend_db.insert_object(fw)
    backend_db.insert_object(fo)
    insert_test_fw(backend_db, 'some_other_fw')

    assert frontend_db.generic_search({'file_name': 'foo.bar'}, only_fo_parent_firmware=True) == [fw.uid]
    assert frontend_db.generic_search({'file_name': 'foo.bar'}, only_fo_parent_firmware=True, inverted=True) == [
        'some_other_fw'
    ]


def test_search_limit_skip_and_order(frontend_db, backend_db):
    insert_test_fw(backend_db, 'uid_1', device_class='foo', vendor='v1', device_name='n2', file_name='f1')
    insert_test_fw(backend_db, 'uid_2', device_class='foo', vendor='v1', device_name='n3', file_name='f2')
    insert_test_fw(backend_db, 'uid_3', device_class='foo', vendor='v1', device_name='n1', file_name='f3')
    insert_test_fw(backend_db, 'uid_4', device_class='foo', vendor='v2', device_name='n1', file_name='f4')

    expected_result_fw = ['uid_3', 'uid_1', 'uid_2', 'uid_4']
    result = frontend_db.generic_search({})
    assert result == expected_result_fw, 'sorted wrongly (FW sort key should be vendor > device)'
    result = frontend_db.generic_search({'device_class': 'foo'}, only_fo_parent_firmware=True)
    assert result == expected_result_fw, 'sorted wrongly (FW sort key should be vendor > device)'

    expected_result_fo = ['uid_1', 'uid_2', 'uid_3', 'uid_4']
    result = frontend_db.generic_search({'device_class': 'foo'})
    assert result == expected_result_fo, 'sorted wrongly (FO sort key should be file name)'
    result = frontend_db.generic_search({'device_class': 'foo'}, limit=2)
    assert result == expected_result_fo[:2], 'limit does not work correctly'
    result = frontend_db.generic_search({'device_class': 'foo'}, limit=2, skip=2)
    assert result == expected_result_fo[2:], 'skip does not work correctly'


def test_search_analysis_result(frontend_db, backend_db):
    insert_test_fw(backend_db, 'uid_1')
    insert_test_fw(backend_db, 'uid_2')
    backend_db.add_analysis('uid_2', 'test_plugin', generate_analysis_entry(analysis_result={'foo': 'bar', 'test': 3}))
    assert frontend_db.generic_search({'processed_analysis.test_plugin.foo': 'bar'}) == ['uid_2']
    assert frontend_db.generic_search({'processed_analysis.test_plugin.test': 3}) == ['uid_2']


def test_get_other_versions(frontend_db, backend_db):
    insert_test_fw(backend_db, 'uid_1', version='1.0')
    insert_test_fw(backend_db, 'uid_2', version='2.0')
    insert_test_fw(backend_db, 'uid_3', version='3.0')
    fw1 = frontend_db.get_object('uid_1')
    result = frontend_db.get_other_versions_of_firmware(fw1)
    assert result == [('uid_2', '2.0'), ('uid_3', '3.0')]

    assert frontend_db.get_other_versions_of_firmware(TEST_FO) == []


def test_get_latest_comments(frontend_db, backend_db):
    assert frontend_db.get_latest_comments(limit=2) == [], 'no comments in DB should not cause exceptions'

    fo1 = create_test_file_object()
    fo1.comments = [
        {'author': 'anonymous', 'comment': 'comment1', 'time': '1'},
        {'author': 'anonymous', 'comment': 'comment3', 'time': '3'},
    ]
    backend_db.insert_object(fo1)
    fo2 = create_test_file_object()
    fo2.uid = 'fo2_uid'
    fo2.comments = [{'author': 'foo', 'comment': 'comment2', 'time': '2'}]
    backend_db.insert_object(fo2)

    assert (
        len(frontend_db.get_latest_comments(limit=10)) == 3  # noqa: PLR2004
    ), 'we added 3 comments, so we expect that many here'
    result = frontend_db.get_latest_comments(limit=2)
    assert len(result) == 2  # noqa: PLR2004
    assert result[0]['time'] == '3', 'the first entry should have the newest timestamp'
    assert result[1]['time'] == '2'
    assert result[1]['comment'] == 'comment2'
    assert result[1]['uid'] == 'fo2_uid'


def test_generate_file_tree_level(frontend_db, backend_db):
    child_fo, parent_fw = create_fw_with_child_fo()
    child_fo.processed_analysis['file_type'] = generate_analysis_entry(analysis_result={'mime': 'sometype'})
    uid = parent_fw.uid
    child_fo.virtual_file_path = {uid: [f'/folder/{child_fo.file_name}']}
    backend_db.insert_multiple_objects(parent_fw, child_fo)
    for node in frontend_db.generate_file_tree_level(uid, uid):
        assert isinstance(node, FileTreeNode)
        assert node.name == parent_fw.file_name
        assert node.has_children
    for node in frontend_db.generate_file_tree_level(child_fo.uid, root_uid=uid, parent_uid=uid):
        assert isinstance(node, FileTreeNode)
        assert node.name == 'folder'
        assert node.has_children
        virtual_grand_child = node.get_list_of_child_nodes()[0]
        assert virtual_grand_child.type == 'sometype'
        assert not virtual_grand_child.has_children
        assert virtual_grand_child.name == child_fo.file_name


def test_get_file_tree_data(frontend_db, backend_db):
    fw, parent_fo, child_fo = create_fw_with_parent_and_child()
    fw.processed_analysis = {'file_type': generate_analysis_entry(analysis_result={'failed': 'some error'})}
    parent_fo.processed_analysis = {'file_type': generate_analysis_entry(analysis_result={'mime': 'foo_type'})}
    child_fo.processed_analysis = {}  # simulate that file_type did not run yet
    backend_db.insert_multiple_objects(fw, parent_fo, child_fo)

    result = frontend_db.get_file_tree_data([fw.uid, parent_fo.uid, child_fo.uid])
    assert len(result) == 3  # noqa: PLR2004
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
    ('query', 'expected', 'expected_fw', 'expected_inv'),
    [
        ({}, 1, 1, 1),
        ({'size': 123}, 2, 1, 0),
        ({'file_name': 'foo.bar'}, 1, 1, 0),
        ({'vendor': 'test_vendor'}, 1, 1, 0),
    ],
)
def test_get_number_of_total_matches(frontend_db, backend_db, query, expected, expected_fw, expected_inv):
    fw, parent_fo, child_fo = create_fw_with_parent_and_child()
    fw.vendor = 'test_vendor'
    parent_fo.size = 123
    child_fo.size = 123
    child_fo.file_name = 'foo.bar'
    backend_db.insert_multiple_objects(fw, parent_fo, child_fo)
    assert frontend_db.get_number_of_total_matches(query, only_parent_firmwares=False, inverted=False) == expected
    assert frontend_db.get_number_of_total_matches(query, only_parent_firmwares=True, inverted=False) == expected_fw
    assert frontend_db.get_number_of_total_matches(query, only_parent_firmwares=True, inverted=True) == expected_inv


def test_rest_get_file_object_uids(frontend_db, backend_db):
    insert_test_fo(backend_db, 'fo1', 'file_name_1', size=10)
    insert_test_fo(backend_db, 'fo2', size=10)
    insert_test_fo(backend_db, 'fo3', size=11)

    assert sorted(frontend_db.rest_get_file_object_uids(offset=None, limit=None)) == ['fo1', 'fo2', 'fo3']
    assert frontend_db.rest_get_file_object_uids(offset=1, limit=1) == ['fo2']
    assert frontend_db.rest_get_file_object_uids(offset=None, limit=None, query={'file_name': 'file_name_1'}) == ['fo1']
    assert frontend_db.rest_get_file_object_uids(offset=None, limit=None, query={'file_name': 'non-existent'}) == []
    assert sorted(frontend_db.rest_get_file_object_uids(offset=None, limit=None, query={'size': 10})) == ['fo1', 'fo2']


def test_rest_get_firmware_uids(frontend_db, backend_db):
    child_fo, parent_fw = create_fw_with_child_fo()
    child_fo.file_name = 'foo_file'
    backend_db.insert_multiple_objects(parent_fw, child_fo)
    test_fw1 = insert_test_fw(backend_db, 'fw1', vendor='foo_vendor', file_name='fw1', device_name='some_device')
    test_fw2 = insert_test_fw(backend_db, 'fw2', vendor='foo_vendor', file_name='fw2')

    assert sorted(frontend_db.rest_get_firmware_uids(offset=None, limit=None)) == [
        parent_fw.uid,
        test_fw1.uid,
        test_fw2.uid,
    ]
    assert sorted(frontend_db.rest_get_firmware_uids(query={}, offset=0, limit=0)) == [
        parent_fw.uid,
        test_fw1.uid,
        test_fw2.uid,
    ]
    assert frontend_db.rest_get_firmware_uids(offset=1, limit=1) == [test_fw1.uid]
    assert sorted(frontend_db.rest_get_firmware_uids(offset=None, limit=None, query={'vendor': 'foo_vendor'})) == [
        test_fw1.uid,
        test_fw2.uid,
    ]
    assert sorted(
        frontend_db.rest_get_firmware_uids(offset=None, limit=None, query={'device_name': 'some_device'})
    ) == [test_fw1.uid]
    assert sorted(
        frontend_db.rest_get_firmware_uids(offset=None, limit=None, query={'file_name': parent_fw.file_name})
    ) == [parent_fw.uid]
    assert sorted(
        frontend_db.rest_get_firmware_uids(
            offset=None, limit=None, query={'file_name': child_fo.file_name}, recursive=True
        )
    ) == [parent_fw.uid]
    assert sorted(
        frontend_db.rest_get_firmware_uids(
            offset=None, limit=None, query={'file_name': child_fo.file_name}, recursive=True, inverted=True
        )
    ) == [test_fw1.uid, test_fw2.uid]


def test_find_missing_analyses(frontend_db, backend_db):
    fw, parent_fo, child_fo = create_fw_with_parent_and_child()
    fw.processed_analysis = {'plugin1': DUMMY_RESULT, 'plugin2': DUMMY_RESULT, 'plugin3': DUMMY_RESULT}
    parent_fo.processed_analysis = {'plugin1': DUMMY_RESULT, 'plugin2': DUMMY_RESULT}
    child_fo.processed_analysis = {'plugin1': DUMMY_RESULT}
    backend_db.insert_object(fw)
    backend_db.insert_object(parent_fo)
    backend_db.insert_object(child_fo)

    assert frontend_db.find_missing_analyses() == {fw.uid: {parent_fo.uid, child_fo.uid}}


def test_find_failed_analyses(frontend_db, backend_db):
    failed_result = generate_analysis_entry(analysis_result={'failed': 'it failed'})
    insert_test_fo(backend_db, 'fo1', analysis={'plugin1': DUMMY_RESULT, 'plugin2': failed_result})
    insert_test_fo(backend_db, 'fo2', analysis={'plugin1': failed_result, 'plugin2': failed_result})

    assert frontend_db.find_failed_analyses() == {'plugin1': {'fo2'}, 'plugin2': {'fo1', 'fo2'}}


def test_get_tag_list(frontend_db, backend_db):
    assert frontend_db.get_tag_list() == []

    insert_test_fw(backend_db, uid='fw_1', tags={'foo': 'some_color', 'bar': 'some_color'})
    insert_test_fw(backend_db, uid='fw_2', tags={'foo': 'some_color', 'test': 'some_color'})

    assert frontend_db.get_tag_list() == ['bar', 'foo', 'test']


# --- search cache ---


def test_get_query_from_cache(frontend_db, frontend_editing_db):
    assert frontend_db.get_query_from_cache('non-existent') is None

    match_data = {'uid': {'rule': []}}
    id_ = frontend_editing_db.add_to_search_query_cache('foo', match_data, 'bar')
    entry = frontend_db.get_query_from_cache(id_)
    assert isinstance(entry, CachedQuery)
    assert entry.query == 'foo'
    assert entry.yara_rule == 'bar'
    assert entry.match_data == match_data


def test_get_cached_count(frontend_db, frontend_editing_db):
    assert frontend_db.get_total_cached_query_count() == 0

    frontend_editing_db.add_to_search_query_cache('foo', {}, 'bar')
    assert frontend_db.get_total_cached_query_count() == 1

    frontend_editing_db.add_to_search_query_cache('bar', {}, 'foo')
    assert frontend_db.get_total_cached_query_count() == 2  # noqa: PLR2004


def test_search_query_cache(frontend_db, frontend_editing_db):
    assert frontend_db.search_query_cache(offset=0, limit=10) == []

    id1 = frontend_editing_db.add_to_search_query_cache('foo', {}, 'rule bar{}')
    id2 = frontend_editing_db.add_to_search_query_cache('bar', {}, 'rule foo{}')
    assert sorted(frontend_db.search_query_cache(offset=0, limit=10)) == [
        (id1, 'rule bar{}', ['bar']),
        (id2, 'rule foo{}', ['foo']),
    ]


def test_data_for_dependency_graph(frontend_db, backend_db):
    child_fo, parent_fw = create_fw_with_child_fo()
    assert frontend_db.get_data_for_dependency_graph(parent_fw.uid) == []

    backend_db.insert_multiple_objects(parent_fw, child_fo)

    assert frontend_db.get_data_for_dependency_graph(child_fo.uid) == [], 'should be empty if no files included'

    result = frontend_db.get_data_for_dependency_graph(parent_fw.uid)
    assert len(result) == 1
    assert isinstance(result[0], DepGraphData)
    assert result[0].uid == child_fo.uid
    assert result[0].libraries is None
    assert result[0].full_type == 'Not a PE file'
    assert result[0].file_name == 'testfile1'
    assert result[0].virtual_file_paths == ['/folder/testfile1']


def test_get_root_uid(frontend_db, backend_db):
    child_fo, parent_fw = create_fw_with_child_fo()
    backend_db.insert_multiple_objects(parent_fw, child_fo)
    assert frontend_db.get_root_uid(child_fo.uid) == parent_fw.uid
    assert frontend_db.get_root_uid(parent_fw.uid) == parent_fw.uid
