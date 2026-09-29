from __future__ import annotations

import json
from queue import Queue

from web_interface.components import sse_routes


def test_status_stream_headers_and_heartbeat(test_client):
    """The endpoint returns an event stream with proxy buffers disabled, and the
    FakeSSEQueue emits an immediate heartbeat so the stream is readable without
    any redis."""
    response = test_client.get('/status-stream', buffered=False)
    assert response.status_code == 200
    assert response.mimetype == 'text/event-stream'
    assert response.headers.get('X-Accel-Buffering') == 'no'

    line = ''
    for chunk in response.iter_encoded():
        decoded = chunk.decode()
        if decoded.startswith('data:'):
            line = decoded
            break

    assert json.loads(line.removeprefix('data: ')) == {'type': 'heartbeat'}

    response.close()


class PublisherStub:
    def __init__(self, queue: Queue):
        self.queue = queue
        self.removed = False

    @staticmethod
    def get_last_status_snapshot():
        return ['{"name": "backend"}']

    def add_subscriber(self):
        return self.queue

    def remove_subscriber(self, _queue):
        self.removed = True


def test_stream_ends_on_publisher_shutdown(web_frontend):
    queue = Queue()
    queue.put('{"name": "frontend"}')
    queue.put(None)  # shutdown sentinel
    web_frontend.sse.sse_publisher = publisher = PublisherStub(queue)

    messages = list(web_frontend.sse._event_generator())

    assert messages == ['retry: 1000\n\n', 'data: {"name": "backend"}\n\n', 'data: {"name": "frontend"}\n\n']
    assert publisher.removed


def test_stream_ends_after_max_duration(web_frontend, monkeypatch):
    monkeypatch.setattr(sse_routes, 'MAX_STREAM_DURATION', 0)
    web_frontend.sse.sse_publisher = publisher = PublisherStub(Queue())

    messages = list(web_frontend.sse._event_generator())

    assert messages == ['retry: 1000\n\n', 'data: {"name": "backend"}\n\n']
    assert publisher.removed
