from __future__ import annotations

import json
import time
from queue import Empty
from uuid import uuid4

import pytest

from storage.redis_sse_publisher import RedisSSEPublisher
from storage.redis_status_interface import RedisStatusInterface


@pytest.fixture
def status_interface():
    interface = RedisStatusInterface()
    yield interface
    interface.redis.redis.flushdb()


@pytest.fixture
def publisher(status_interface):
    publisher = RedisSSEPublisher(status_interface=status_interface)
    yield publisher
    publisher.shutdown()


def _wait_for_subscription(publisher: RedisSSEPublisher, timeout: float = 5):
    deadline = time.monotonic() + timeout
    while publisher.pubsub is None or not publisher.pubsub.subscribed:
        assert time.monotonic() < deadline, 'listener did not subscribe in time'
        time.sleep(0.01)


def _get_status_with_marker(queue, marker: str, timeout: float = 5) -> dict:
    # pub/sub channels are not scoped to Redis DBs -> other messages on the channel are possible and must be skipped
    deadline = time.monotonic() + timeout
    while (remaining := deadline - time.monotonic()) > 0:
        try:
            status = json.loads(queue.get(timeout=remaining))
        except Empty:
            break
        if status.get('marker') == marker:
            return status
    raise AssertionError('status update was not received')


def test_status_update_is_forwarded_to_subscribers(status_interface, publisher):
    subscriber_queue = publisher.add_subscriber()
    _wait_for_subscription(publisher)
    marker = str(uuid4())

    status_interface.set_component_status('backend', {'name': 'backend', 'status': 'online', 'marker': marker})

    status = _get_status_with_marker(subscriber_queue, marker)
    assert status['status'] == 'online'
    assert status['_id'] == 'backend'


def test_snapshot_is_initialized_from_redis(status_interface):
    marker = str(uuid4())
    status_interface.set_component_status('frontend', {'name': 'frontend', 'status': 'online', 'marker': marker})

    publisher = RedisSSEPublisher(status_interface=status_interface)
    try:
        # the snapshot is initialized by the listener thread after subscribing -> wait for it
        deadline = time.monotonic() + 5
        while not any(json.loads(s).get('marker') == marker for s in publisher.get_last_status_snapshot()):
            assert time.monotonic() < deadline, 'snapshot was not initialized in time'
            time.sleep(0.01)
    finally:
        publisher.shutdown()
