# pylint: disable=redefined-outer-name

import pytest

from storage_postgresql.db_interface_stats import StatsDbUpdater, StatsDbViewer
from storage_postgresql.schema import FileObjectEntry, StatsEntry
from test.common_helper import create_test_firmware  # pylint: disable=wrong-import-order


@pytest.fixture
def stats_updater():
    updater = StatsDbUpdater(database='fact_test2')
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

    result = stats_updater.get_sum(FileObjectEntry.size)
    assert result == 100


def test_get_avg(db, stats_updater):
    fw1 = create_test_firmware()
    fw1.uid = 'fw1'
    fw1.size = 33
    db.backend.add_object(fw1)
    fw2 = create_test_firmware()
    fw2.uid = 'fw2'
    fw2.size = 67
    db.backend.add_object(fw2)

    result = stats_updater.get_avg(FileObjectEntry.size)
    assert round(result) == 50
