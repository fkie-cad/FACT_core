from __future__ import annotations

import json
import time
from queue import Full, Queue

import pytest
from redis.exceptions import ConnectionError as RedisConnectionError

from storage import redis_sse_publisher
from storage.redis_sse_publisher import RedisSSEPublisher
from storage.redis_status_interface import PUBSUB_CHANNEL


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

    def test_client_empties_full_queue_concurrently(self, publisher):
        class RacyQueue(Queue):
            """the queue is full on `put`, but the client empties it before the publisher can drop the oldest item"""

            def __init__(self):
                super().__init__(maxsize=1)
                self.first_put = True

            def put_nowait(self, item):
                if self.first_put:
                    self.first_put = False
                    raise Full
                super().put_nowait(item)

        subscriber_queue = RacyQueue()
        publisher.subscribers.add(subscriber_queue)

        publisher._handle_message(_message({'name': 'backend', 'n': 1}))

        assert subscriber_queue in publisher.subscribers  # must not be dropped
        assert json.loads(subscriber_queue.get_nowait()) == {'name': 'backend', 'n': 1}

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


class StatusInterfaceStub:
    @staticmethod
    def get_component_status(component):
        return {'name': component, 'status': 'online'} if component == 'backend' else None

    @staticmethod
    def get_analysis_status():
        return {'current_analyses': {}, 'recently_finished_analyses': {}}


class TestInitSnapshot:
    def test_init_snapshot_from_redis(self):
        publisher = RedisSSEPublisher(status_interface=StatusInterfaceStub(), start_listener=False)
        publisher._init_snapshot()

        snapshot = sorted(json.loads(s).get('name', 'analysis') for s in publisher.last_status.values())
        assert snapshot == ['analysis', 'backend']  # missing components are skipped

    def test_newer_message_overrides_seed(self):
        publisher = RedisSSEPublisher(status_interface=StatusInterfaceStub(), start_listener=False)
        publisher._init_snapshot()
        publisher._handle_message(_message({'name': 'backend', 'status': 'offline'}))

        assert json.loads(publisher.last_status['backend'])['status'] == 'offline'


class TestShutdown:
    def test_shutdown_stops_subscribers(self, publisher):
        subscriber_queue = publisher.add_subscriber()
        full_queue: Queue = Queue(maxsize=1)
        full_queue.put('update')
        publisher.subscribers.add(full_queue)

        publisher.shutdown()

        assert subscriber_queue.get_nowait() is None
        assert full_queue.get_nowait() is None  # even works if the queue is full

    def test_cleanup_closes_pubsub_only_once(self, publisher):
        publisher.pubsub = pubsub = FakePubSub([])

        publisher.shutdown()
        publisher.shutdown()

        assert pubsub.unsubscribe_calls == 1
        assert pubsub.closed
        assert publisher.pubsub is None


class FakePubSub:
    def __init__(self, messages: list[dict | Exception]):
        self.messages = messages
        self.subscribed: list[str] = []
        self.unsubscribe_calls = 0
        self.closed = False

    def subscribe(self, channel):
        self.subscribed.append(channel)

    def get_message(self, timeout):
        if self.messages:
            message = self.messages.pop(0)
            if isinstance(message, Exception):
                raise message
            return message
        time.sleep(min(timeout, 0.01))
        return None

    def unsubscribe(self):
        self.unsubscribe_calls += 1

    def close(self):
        self.closed = True


class FakeRedis:
    def __init__(self, *pubsubs: FakePubSub):
        self.pubsubs = list(pubsubs)
        self.created: list[FakePubSub] = []

    def pubsub(self):
        pubsub = self.pubsubs.pop(0) if self.pubsubs else FakePubSub([])
        self.created.append(pubsub)
        return pubsub


def _wait_until(condition, timeout: float = 2):
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline, 'timeout while waiting for condition'
        time.sleep(0.01)


def _redis_message(payload: dict) -> dict:
    return {'type': 'message', 'data': json.dumps(payload).encode()}


class TestListener:
    @pytest.fixture
    def listener_publisher(self, request):
        publisher = RedisSSEPublisher(
            redis_client=FakeRedis(*request.param),
            status_interface=StatusInterfaceStub(),
            start_listener=False,
        )
        yield publisher
        publisher.shutdown()

    @pytest.mark.parametrize(
        'listener_publisher',
        [[FakePubSub([{'type': 'subscribe', 'data': 1}, _redis_message({'name': 'backend', 'n': 1})])]],
        indirect=True,
    )
    def test_listener_forwards_messages(self, listener_publisher):
        subscriber_queue = listener_publisher.add_subscriber()
        listener_publisher._start_redis_listener()

        # the "subscribe" confirmation is ignored and only the actual message is forwarded
        assert json.loads(subscriber_queue.get(timeout=2)) == {'name': 'backend', 'n': 1}
        pubsub = listener_publisher.redis.created[0]
        assert pubsub.subscribed == [PUBSUB_CHANNEL]
        # the snapshot was initialized from redis (analysis status) and updated by the message (backend)
        snapshot = [json.loads(s) for s in listener_publisher.get_last_status_snapshot()]
        assert {'name': 'backend', 'n': 1} in snapshot
        assert any('current_analyses' in status for status in snapshot)

        listener_publisher.shutdown()

        assert not listener_publisher.proc.is_alive()
        assert listener_publisher._listener_stopped.is_set()
        assert pubsub.closed
        assert subscriber_queue.get_nowait() is None  # the stream is notified of the shutdown

    @pytest.mark.parametrize(
        'listener_publisher',
        [
            [
                FakePubSub([RedisConnectionError('connection lost')]),
                FakePubSub([_redis_message({'name': 'backend', 'n': 2})]),
            ]
        ],
        indirect=True,
    )
    def test_listener_reconnects_after_error(self, listener_publisher, monkeypatch):
        monkeypatch.setattr(redis_sse_publisher, 'INITIAL_RECONNECT_BACKOFF', 0.01)
        subscriber_queue = listener_publisher.add_subscriber()
        listener_publisher._start_redis_listener()

        assert json.loads(subscriber_queue.get(timeout=2)) == {'name': 'backend', 'n': 2}
        broken_pubsub, new_pubsub = listener_publisher.redis.created[:2]
        assert broken_pubsub.closed
        assert new_pubsub.subscribed == [PUBSUB_CHANNEL]

    @pytest.mark.parametrize('listener_publisher', [[FakePubSub([RedisConnectionError('down')])]], indirect=True)
    def test_shutdown_during_reconnect_backoff(self, listener_publisher, monkeypatch):
        monkeypatch.setattr(redis_sse_publisher, 'INITIAL_RECONNECT_BACKOFF', 30)
        listener_publisher._start_redis_listener()
        created = listener_publisher.redis.created
        _wait_until(lambda: created and created[0].closed)  # the listener is now in the backoff phase

        start = time.monotonic()
        listener_publisher.shutdown()

        assert time.monotonic() - start < 1  # the backoff wait is interrupted by the shutdown
        assert not listener_publisher.proc.is_alive()
