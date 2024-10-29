from math import isclose

import pytest

from storage.db_interface_stats import StatsDbViewer, count_occurrences
from storage.schema import AnalysisEntry, FileObjectEntry, FirmwareEntry, StatsEntry
from test.common_helper import (
    create_test_file_object,
    create_test_firmware,
    generate_analysis_entry,
)

from .helper import create_fw_with_parent_and_child, insert_test_fo, insert_test_fw


@pytest.fixture
def stats_viewer():
    return StatsDbViewer()


def test_update_stats(stats_update_db):
    with stats_update_db.get_read_only_session() as session:
        assert session.get(StatsEntry, 'foo') is None

    # insert
    stats_data = {'stat': [('foo', 1), ('bar', 2)]}
    stats_update_db.update_statistic('foo', stats_data)

    with stats_update_db.get_read_only_session() as session:
        entry = session.get(StatsEntry, 'foo')
        assert entry is not None
        assert entry.name == 'foo'
        assert entry.data['stat'] == [list(entry) for entry in stats_data['stat']]

    # update
    stats_update_db.update_statistic('foo', {'foo': '123'})

    with stats_update_db.get_read_only_session() as session:
        entry = session.get(StatsEntry, 'foo')
        assert entry.data['foo'] == '123'


def test_get_stats(stats_update_db, stats_viewer):
    assert stats_viewer.get_statistic('foo') is None

    stats_update_db.update_statistic('foo', {'foo': 'bar'})

    assert stats_viewer.get_statistic('foo') == {'_id': 'foo', 'foo': 'bar'}


def test_get_stats_list(stats_update_db, stats_viewer):
    stats_update_db.update_statistic('foo', {'foo': 'bar'})
    stats_update_db.update_statistic('bar', {'bar': 'foo'})
    stats_update_db.update_statistic('test', {'test': '123'})

    result = stats_viewer.get_stats_list('foo', 'bar')

    assert len(result) == 2
    expected_results = [
        {'_id': 'foo', 'foo': 'bar'},
        {'_id': 'bar', 'bar': 'foo'},
    ]
    assert all(r in result for r in expected_results)

    assert stats_viewer.get_stats_list() == []


def test_get_sum(stats_update_db, backend_db):
    fw1 = create_test_firmware()
    fw1.uid = 'fw1'
    fw1.size = 33
    backend_db.add_object(fw1)
    fw2 = create_test_firmware()
    fw2.uid = 'fw2'
    fw2.size = 67
    backend_db.add_object(fw2)

    result = stats_update_db.get_sum(FileObjectEntry.size, firmware=True)
    assert result == 100


def test_get_fw_count(stats_update_db, backend_db):
    assert stats_update_db.get_count(firmware=True) == 0

    fw1 = create_test_firmware()
    fw1.uid = 'fw1'
    backend_db.add_object(fw1)

    assert stats_update_db.get_count(firmware=True) == 1

    fw2 = create_test_firmware()
    fw2.uid = 'fw2'
    backend_db.add_object(fw2)

    assert stats_update_db.get_count(firmware=True) == 2


def test_get_fo_count(stats_update_db, backend_db):
    fw, parent_fo, child_fo = create_fw_with_parent_and_child()
    backend_db.add_object(fw)
    assert stats_update_db.get_count(firmware=False) == 0
    backend_db.add_object(parent_fo)
    assert stats_update_db.get_count(firmware=False) == 1
    backend_db.add_object(child_fo)
    assert stats_update_db.get_count(firmware=False) == 2


def test_get_included_sum(stats_update_db, backend_db):
    fw, parent_fo, child_fo = create_fw_with_parent_and_child()
    fw.size, parent_fo.size, child_fo.size = 1337, 25, 175
    backend_db.add_object(fw)
    backend_db.add_object(parent_fo)
    backend_db.add_object(child_fo)

    result = stats_update_db.get_sum(FileObjectEntry.size, firmware=False)
    assert result == 200


def test_filtered_included_sum(stats_update_db, backend_db):
    fw, parent_fo, child_fo = create_fw_with_parent_and_child()
    fw.size, parent_fo.size, child_fo.size = 1337, 17, 13
    fw.vendor = 'foo'
    backend_db.add_object(fw)
    backend_db.add_object(parent_fo)
    backend_db.add_object(child_fo)

    # add another FW to check that the filter works
    fo2 = create_test_file_object()
    fw2 = create_test_firmware()
    fw2.uid, fo2.uid = 'other fw uid', 'other fo uid'
    fw2.vendor = 'other vendor'
    fo2.parents.append(fw2.uid)
    fo2.parent_firmware_uids.add(fw2.uid)
    fw2.size, fo2.size = 69, 70
    backend_db.add_object(fw2)
    backend_db.add_object(fo2)

    assert stats_update_db.get_sum(FileObjectEntry.size, firmware=False) == 100
    assert stats_update_db.get_sum(FileObjectEntry.size, q_filter={'vendor': fw.vendor}, firmware=False) == 30
    assert stats_update_db.get_sum(FileObjectEntry.size, q_filter={'vendor': fw2.vendor}, firmware=False) == 70
    assert stats_update_db.get_sum(FileObjectEntry.size, q_filter={'vendor': fw.vendor}, firmware=True) == 1337


def test_get_avg(stats_update_db, backend_db):
    fw1 = create_test_firmware()
    fw1.uid = 'fw1'
    fw1.size = 33
    backend_db.add_object(fw1)
    fw2 = create_test_firmware()
    fw2.uid = 'fw2'
    fw2.size = 67
    backend_db.add_object(fw2)

    result = stats_update_db.get_avg(FileObjectEntry.size, firmware=True)
    assert round(result) == 50


def test_count_distinct_values(backend_db, stats_update_db):
    insert_test_fw(backend_db, 'fw1', device_class='class', vendor='vendor_1', device_name='device_1')
    insert_test_fw(backend_db, 'fw2', device_class='class', vendor='vendor_2', device_name='device_2')
    insert_test_fw(backend_db, 'fw3', device_class='class', vendor='vendor_1', device_name='device_3')

    assert stats_update_db.count_distinct_values(FirmwareEntry.device_class) == [('class', 3)]
    assert stats_update_db.count_distinct_values(FirmwareEntry.vendor) == [
        ('vendor_2', 1),
        ('vendor_1', 2),
    ], 'sorted wrongly'
    assert sorted(stats_update_db.count_distinct_values(FirmwareEntry.device_name)) == [
        ('device_1', 1),
        ('device_2', 1),
        ('device_3', 1),
    ]


@pytest.mark.parametrize(
    ('q_filter', 'expected_result'),
    [
        (None, [('value2', 1), ('value1', 2)]),
        ({'vendor': 'foobar'}, [('value1', 2)]),
    ],
)
def test_count_distinct_analysis(backend_db, stats_update_db, q_filter, expected_result):
    insert_test_fw(backend_db, 'root_fw', vendor='foobar')
    insert_test_fw(backend_db, 'another_fw', vendor='another_vendor')
    insert_test_fo(
        backend_db,
        'fo1',
        analysis={'foo': generate_analysis_entry(analysis_result={'key': 'value1', 'x': 0})},
        parent_fw='root_fw',
    )
    insert_test_fo(
        backend_db,
        'fo2',
        analysis={'foo': generate_analysis_entry(analysis_result={'key': 'value1', 'x': 1})},
        parent_fw='root_fw',
    )
    insert_test_fo(
        backend_db,
        'fo3',
        analysis={'foo': generate_analysis_entry(analysis_result={'key': 'value2', 'x': 0})},
        parent_fw='another_fw',
    )

    result = stats_update_db.count_distinct_in_analysis(AnalysisEntry.result['key'], plugin='foo', q_filter=q_filter)
    assert result == expected_result


def test_count_values_in_summary(backend_db, stats_update_db):
    fw, parent_fo, child_fo = create_fw_with_parent_and_child()
    fw.processed_analysis = {'foo': generate_analysis_entry(summary=['s1', 's2'])}
    parent_fo.processed_analysis = {'foo': generate_analysis_entry(summary=['s3', 's4'])}
    child_fo.processed_analysis = {'foo': generate_analysis_entry(summary=['s4'])}
    backend_db.add_object(fw)
    backend_db.add_object(parent_fo)
    backend_db.add_object(child_fo)

    assert stats_update_db.count_values_in_summary('plugin that did not run', firmware=True) == []
    assert stats_update_db.count_values_in_summary('foo', firmware=True) == [('s1', 1), ('s2', 1)]
    assert stats_update_db.count_values_in_summary('foo', firmware=True, q_filter={'vendor': fw.vendor}) == [
        ('s1', 1),
        ('s2', 1),
    ]
    assert stats_update_db.count_values_in_summary('foo', firmware=False) == [('s3', 1), ('s4', 2)]
    assert stats_update_db.count_values_in_summary('foo', firmware=False, q_filter={'vendor': fw.vendor}) == [
        ('s3', 1),
        ('s4', 2),
    ]
    assert stats_update_db.count_values_in_summary('foo', firmware=False, q_filter={'vendor': 'different'}) == []


@pytest.mark.parametrize(
    ('q_filter', 'plugin', 'expected_result'),
    [
        (None, 'foo', [('value2', 1), ('value1', 2)]),
        (None, 'other', []),
        ({'vendor': 'foobar'}, 'foo', [('value2', 1), ('value1', 2)]),
        ({'vendor': 'unknown'}, 'foo', []),
    ],
)
def test_count_distinct_array(backend_db, stats_update_db, q_filter, plugin, expected_result):
    insert_test_fw(backend_db, 'root_fw', vendor='foobar')
    insert_test_fo(
        backend_db,
        'fo1',
        parent_fw='root_fw',
        analysis={'foo': generate_analysis_entry(analysis_result={'key': ['value1']})},
    )
    insert_test_fo(
        backend_db,
        'fo2',
        parent_fw='root_fw',
        analysis={'foo': generate_analysis_entry(analysis_result={'key': ['value1', 'value2']})},
    )

    stats = stats_update_db.count_distinct_values_in_array(
        AnalysisEntry.result['key'], plugin=plugin, q_filter=q_filter
    )
    assert stats == expected_result


def test_get_unpacking_file_types(backend_db, stats_update_db):
    insert_test_fw(
        backend_db,
        'root_fw',
        vendor='foobar',
        analysis={
            'unpacker': generate_analysis_entry(summary=['unpacked']),
            'file_type': generate_analysis_entry(analysis_result={'mime': 'firmware/image'}),
        },
    )
    insert_test_fo(
        backend_db,
        'fo1',
        parent_fw='root_fw',
        analysis={
            'unpacker': generate_analysis_entry(summary=['packed']),
            'file_type': generate_analysis_entry(analysis_result={'mime': 'some/file'}),
        },
    )

    assert stats_update_db.get_unpacking_file_types('unpacked') == [('firmware/image', 1)]
    assert stats_update_db.get_unpacking_file_types('packed') == [('some/file', 1)]
    assert stats_update_db.get_unpacking_file_types('packed', q_filter={'vendor': 'foobar'}) == [('some/file', 1)]
    assert stats_update_db.get_unpacking_file_types('packed', q_filter={'vendor': 'other'}) == []


def test_get_unpacking_entropy(backend_db, stats_update_db):
    insert_test_fw(
        backend_db,
        'root_fw',
        vendor='foobar',
        analysis={
            'unpacker': generate_analysis_entry(summary=['unpacked'], analysis_result={'entropy': 0.4}),
        },
    )
    insert_test_fo(
        backend_db,
        'fo1',
        parent_fw='root_fw',
        analysis={
            'unpacker': generate_analysis_entry(summary=['unpacked'], analysis_result={'entropy': 0.6}),
        },
    )
    insert_test_fo(
        backend_db,
        'fo2',
        parent_fw='root_fw',
        analysis={
            'unpacker': generate_analysis_entry(summary=['packed'], analysis_result={'entropy': 0.8}),
        },
    )

    assert isclose(stats_update_db.get_unpacking_entropy('packed'), 0.8, abs_tol=0.01)
    assert isclose(stats_update_db.get_unpacking_entropy('unpacked'), 0.5, abs_tol=0.01)
    assert isclose(stats_update_db.get_unpacking_entropy('unpacked', q_filter={'vendor': 'foobar'}), 0.5, abs_tol=0.01)
    assert isclose(stats_update_db.get_unpacking_entropy('unpacked', q_filter={'vendor': 'other'}), 0.0, abs_tol=0.01)


def test_get_used_unpackers(backend_db, stats_update_db):
    insert_test_fw(
        backend_db,
        'root_fw',
        vendor='foobar',
        analysis={
            'unpacker': generate_analysis_entry(
                analysis_result={'plugin_used': 'unpacker1', 'number_of_unpacked_files': 10}
            ),
        },
    )
    insert_test_fo(
        backend_db,
        'fo1',
        parent_fw='root_fw',
        analysis={
            'unpacker': generate_analysis_entry(
                analysis_result={'plugin_used': 'unpacker2', 'number_of_unpacked_files': 1}
            ),
        },
    )
    insert_test_fo(
        backend_db,
        'fo2',
        parent_fw='root_fw',
        analysis={
            'unpacker': generate_analysis_entry(
                analysis_result={'plugin_used': 'unpacker3', 'number_of_unpacked_files': 0}
            ),
        },
    )

    assert stats_update_db.get_used_unpackers() == [('unpacker1', 1), ('unpacker2', 1)]
    assert stats_update_db.get_used_unpackers(q_filter={'vendor': 'foobar'}) == [('unpacker1', 1), ('unpacker2', 1)]
    assert stats_update_db.get_used_unpackers(q_filter={'vendor': 'other'}) == []


def test_count_occurrences():
    test_list = ['A', 'B', 'B', 'C', 'C', 'C']
    result = set(count_occurrences(test_list))
    expected_result = {('A', 1), ('C', 3), ('B', 2)}
    assert result == expected_result
