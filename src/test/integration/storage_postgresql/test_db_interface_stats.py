# pylint: disable=redefined-outer-name

import pytest

from storage_postgresql.db_interface_stats import StatsDbViewer, StatsUpdateDbInterface
from storage_postgresql.schema import FileObjectEntry, StatsEntry
from test.common_helper import create_test_file_object, create_test_firmware  # pylint: disable=wrong-import-order

from .helper import create_fw_with_parent_and_child


@pytest.fixture
def stats_updater():
    updater = StatsUpdateDbInterface(database='fact_test2')
    yield updater


@pytest.fixture
def stats_viewer():
    viewer = StatsDbViewer(database='fact_test2')
    yield viewer


def test_update_stats(db, stats_updater):  # pylint: disable=unused-argument
    with stats_updater.get_read_only_session() as session:
        assert session.get(StatsEntry, 'foo') is None

    # insert
    stats_data = {'foo': 'bar'}
    stats_updater.update_statistic('foo', stats_data)

    with stats_updater.get_read_only_session() as session:
        entry = session.get(StatsEntry, 'foo')
        assert entry is not None
        assert entry.name == 'foo'
        assert entry.data == stats_data

    # update
    stats_updater.update_statistic('foo', {'foo': '123'})

    with stats_updater.get_read_only_session() as session:
        entry = session.get(StatsEntry, 'foo')
        assert entry.data['foo'] == '123'


def test_get_stats(db, stats_updater, stats_viewer):  # pylint: disable=unused-argument
    assert stats_viewer.get_statistic('foo') is None

    stats_updater.update_statistic('foo', {'foo': 'bar'})

    assert stats_viewer.get_statistic('foo') == {'_id': 'foo', 'foo': 'bar'}


def test_get_stats_list(db, stats_updater, stats_viewer):  # pylint: disable=unused-argument
    stats_updater.update_statistic('foo', {'foo': 'bar'})
    stats_updater.update_statistic('bar', {'bar': 'foo'})
    stats_updater.update_statistic('test', {'test': '123'})

    result = stats_viewer.get_stats_list('foo', 'bar')

    assert len(result) == 2
    expected_results = [
        {'_id': 'foo', 'foo': 'bar'},
        {'_id': 'bar', 'bar': 'foo'},
    ]
    assert all(r in result for r in expected_results)

    assert stats_viewer.get_stats_list() == []


def test_get_sum(db, stats_updater):
    fw1 = create_test_firmware()
    fw1.uid = 'fw1'
    fw1.size = 33
    db.backend.add_object(fw1)
    fw2 = create_test_firmware()
    fw2.uid = 'fw2'
    fw2.size = 67
    db.backend.add_object(fw2)

    result = stats_updater.get_sum(FileObjectEntry.size, firmware=True)
    assert result == 100


def test_get_included_sum(db, stats_updater):
    fw, parent_fo, child_fo = create_fw_with_parent_and_child()
    fw.size, parent_fo.size, child_fo.size = 1337, 25, 175
    db.backend.add_object(fw)
    db.backend.add_object(parent_fo)
    db.backend.add_object(child_fo)

    result = stats_updater.get_sum(FileObjectEntry.size, firmware=False)
    assert result == 200


def test_filtered_included_sum(db, stats_updater):
    fw, parent_fo, child_fo = create_fw_with_parent_and_child()
    fw.size, parent_fo.size, child_fo.size = 1337, 17, 13
    fw.vendor = 'foo'
    db.backend.add_object(fw)
    db.backend.add_object(parent_fo)
    db.backend.add_object(child_fo)

    # add another FW to check that the filter works
    fo2 = create_test_file_object()
    fw2 = create_test_firmware()
    fw2.uid, fo2.uid = 'other fw uid', 'other fo uid'
    fw2.vendor = 'other vendor'
    fo2.parents.append(fw2.uid)
    fo2.parent_firmware_uids.add(fw2.uid)
    fw2.size, fo2.size = 69, 70
    db.backend.add_object(fw2)
    db.backend.add_object(fo2)

    assert stats_updater.get_sum(FileObjectEntry.size, firmware=False) == 100
    assert stats_updater.get_sum(FileObjectEntry.size, filter_={'vendor': fw.vendor}, firmware=False) == 30
    assert stats_updater.get_sum(FileObjectEntry.size, filter_={'vendor': fw2.vendor}, firmware=False) == 70
    assert stats_updater.get_sum(FileObjectEntry.size, filter_={'vendor': fw.vendor}, firmware=True) == 1337


def test_get_avg(db, stats_updater):
    fw1 = create_test_firmware()
    fw1.uid = 'fw1'
    fw1.size = 33
    db.backend.add_object(fw1)
    fw2 = create_test_firmware()
    fw2.uid = 'fw2'
    fw2.size = 67
    db.backend.add_object(fw2)

    result = stats_updater.get_avg(FileObjectEntry.size, firmware=True)
    assert round(result) == 50
