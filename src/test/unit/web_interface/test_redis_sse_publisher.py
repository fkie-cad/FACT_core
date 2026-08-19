from __future__ import annotations

import json
from queue import Queue

import pytest

from storage.redis_sse_publisher import RedisSSEPublisher


def _message(payload: dict) -> dict:
    return {'data': json.dumps(payload).encode()}


@pytest.fixture
def publisher():
    return RedisSSEPublisher(start_listener=False)


class TestHandleMessage:
    def test_deadlock_backpressure_regression(self, publisher):
        # a subscriber that stops consuming -> its bounded queue fills up
        subscriber_queue: Queue = Queue(maxsize=2)
        publisher.subscribers.add(subscriber_queue)

        for i in range(1, 6):
            publisher._handle_message(_message({'name': 'current_analyses', 'n': i}))

        # the test returning at all proves there is no deadlock on the lock
        assert subscriber_queue.qsize() == 2
        latest = [json.loads(s)['n'] for s in list(subscriber_queue.queue)]
        assert latest == [4, 5]  # oldest dropped, latest delivered
        assert subscriber_queue in publisher.subscribers  # backpressure, not eviction

    def test_unchanged_data_is_suppressed(self, publisher):
        subscriber_queue = publisher.add_subscriber()
        payload = {'name': 'current_analyses', 'n': 1}

        publisher._handle_message(_message(payload))
        publisher._handle_message(_message(payload))

        assert publisher.get_last_status_snapshot() == [json.dumps(payload, sort_keys=True)]
        assert subscriber_queue.qsize() == 1

    def test_fan_out_to_multiple_subscribers(self, publisher):
        subscriber_a = publisher.add_subscriber()
        subscriber_b = publisher.add_subscriber()

        publisher._handle_message(_message({'name': 'current_analyses', 'n': 1}))

        assert subscriber_a.qsize() == 1
        assert subscriber_b.qsize() == 1

    def test_unparseable_message_is_ignored(self, publisher):
        publisher._handle_message({'data': b'not json'})
        assert publisher.get_last_status_snapshot() == []

    def test_missing_name_uses_default_key(self, publisher):
        publisher._handle_message(_message({'n': 1}))
        snapshot = publisher.get_last_status_snapshot()
        assert len(snapshot) == 1
        assert json.loads(snapshot[0]) == {'n': 1}


class TestSubscribers:
    def test_add_and_remove_subscriber(self, publisher):
        queue = publisher.add_subscriber()
        assert queue in publisher.subscribers
        publisher.remove_subscriber(queue)
        assert queue not in publisher.subscribers

    def test_remove_unknown_subscriber_is_noop(self, publisher):
        publisher.remove_subscriber(Queue())
        assert publisher.subscribers == set()


class TestSnapshotIsSafeDuringMutation:
    def test_mutation_while_iterating_snapshot(self, publisher):
        publisher._handle_message(_message({'name': 'a', 'n': 1}))
        publisher._handle_message(_message({'name': 'b', 'n': 2}))

        # mutate last_status while holding a snapshot copy
        for status in publisher.get_last_status_snapshot():
            publisher._handle_message(_message({'name': 'c', 'n': 3}))
            assert isinstance(status, str)
