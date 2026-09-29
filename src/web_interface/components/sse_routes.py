from __future__ import annotations

import json
import logging
from queue import Empty
from time import monotonic
from typing import TYPE_CHECKING

from flask import Response

from storage.redis_sse_publisher import RedisSSEPublisher
from web_interface.components.component_base import GET, AppRoute, ComponentBase
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES

if TYPE_CHECKING:
    from collections.abc import Iterator

HEARTBEAT = json.dumps({'type': 'heartbeat'})
CLIENT_POLL_TIMEOUT = 10
# Streams are closed regularly (the browser reconnects automatically and receives a fresh snapshot). Otherwise, a
# graceful uWSGI reload would wait for open streams until the worker mercy timeout (60s) runs out.
MAX_STREAM_DURATION = 30
RECONNECT_DELAY_MS = 1000


class SseRoutes(ComponentBase):
    def __init__(self, *args, sse_publisher: RedisSSEPublisher | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.sse_publisher = sse_publisher or RedisSSEPublisher()

    @roles_accepted(*PRIVILEGES['status'])
    @AppRoute('/status-stream', GET)
    def status_stream(self) -> Response:
        return Response(
            self._event_generator(),
            mimetype='text/event-stream',
            headers={
                'Cache-Control': 'no-cache',
                'X-Accel-Buffering': 'no',
            },
        )

    def _event_generator(self) -> Iterator[str]:
        logging.debug('[system health SSE]: Received subscription request')
        client_queue = self.sse_publisher.add_subscriber()
        deadline = monotonic() + MAX_STREAM_DURATION

        try:
            yield f'retry: {RECONNECT_DELAY_MS}\n\n'
            for status in self.sse_publisher.get_last_status_snapshot():
                yield _sse_message(status)

            while (remaining := deadline - monotonic()) > 0:
                try:
                    data = client_queue.get(timeout=min(CLIENT_POLL_TIMEOUT, remaining))
                except Empty:
                    yield _sse_message(HEARTBEAT)
                    continue
                if data is None:  # publisher shutdown
                    return
                yield _sse_message(data)
        except GeneratorExit:
            pass
        finally:
            self.sse_publisher.remove_subscriber(client_queue)

    def shutdown(self) -> None:
        self.sse_publisher.shutdown()


def _sse_message(data: dict | str) -> str:
    if not isinstance(data, str):
        data = json.dumps(data)
    return f'data: {data}\n\n'
