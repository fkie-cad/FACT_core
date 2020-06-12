from queue import Queue
from time import sleep

import pytest

from scheduler.analysis_tag import TaggingDaemon
from test.common_helper import DatabaseMock, get_config_for_testing


class MockProcess:
    def __init__(self, **kwargs):
        pass

    def start(self):
        pass

    def join(self):
        pass


class MockAnalysisScheduler:
    def __init__(self):
        self.tag_queue = Queue()
        self.config = get_config_for_testing()
        self.db_backend_service = DatabaseMock(None)


@pytest.fixture(scope='function')
def analysis_service():
    return MockAnalysisScheduler()


@pytest.fixture(scope='function')
def scheduler(analysis_service):
    return TaggingDaemon(analysis_scheduler=analysis_service)


@pytest.fixture(scope='function')
def detached_scheduler(monkeypatch, analysis_service):
    monkeypatch.setattr('scheduler.analysis_tag.ExceptionSafeProcess', MockProcess)
    return TaggingDaemon(analysis_scheduler=analysis_service)


def test_start_process(scheduler):
    assert scheduler.tagging_process.is_alive()
    scheduler.stop_condition.value = 1
    sleep(float(scheduler.config['ExpertSettings']['block_delay']) + 1)
    assert not scheduler.tagging_process.is_alive()


def test_shutdown(detached_scheduler):
    detached_scheduler.shutdown()
    assert detached_scheduler.stop_condition.value == 1


def test_fetch_tag(detached_scheduler):
    detached_scheduler.parent.tag_queue.put({'notags': True})
    assert not detached_scheduler.parent.tag_queue.empty()
    detached_scheduler._fetch_next_tag()
    assert detached_scheduler.parent.tag_queue.empty()


def test_process_tags(detached_scheduler):
    mock_queue = Queue()
    setattr(detached_scheduler, '_process_tags', lambda tags: mock_queue.put(tags))
    tags = {'notags': False, 'uid': 'error'}
    detached_scheduler.parent.tag_queue.put(tags)
    detached_scheduler._fetch_next_tag()
    assert mock_queue.get(block=False) == tags


def test_tag_is_put_back_if_uid_does_not_exist(detached_scheduler):
    detached_scheduler.parent.tag_queue.put({'notags': False, 'uid': 'does_not_exist'})
    assert not detached_scheduler.parent.tag_queue.empty()
    detached_scheduler._fetch_next_tag()
    assert not detached_scheduler.parent.tag_queue.empty()


def test_update_tags(detached_scheduler):
    mock_queue = Queue()
    setattr(detached_scheduler.db_interface, 'update_analysis_tags', lambda uid, plugin_name, tag_name, tag: mock_queue.put((uid, plugin_name, tag_name, tag)))
    tags = {'notags': False, 'uid': 'error', 'plugin': 'mock', 'tags': {'tag1': {'propagate': True}, 'tag2': {'propagate': False}}}
    detached_scheduler.parent.tag_queue.put(tags)
    detached_scheduler._fetch_next_tag()
    assert mock_queue.get(block=False) == ('error', 'mock', 'tag1', {'propagate': True})
    assert mock_queue.empty()


def test_empty_queue_times_out(detached_scheduler):
    assert not detached_scheduler._fetch_next_tag()
