from __future__ import annotations

import json
import logging
from queue import Empty
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
                'Connection': 'keep-alive',
                'Access-Control-Allow-Origin': '*',
                'X-Accel-Buffering': 'no',
            },
        )

    def _event_generator(self) -> Iterator[str]:
        logging.debug('[system health SSE]: Received subscription request')
        client_queue = self.sse_publisher.add_subscriber()

        try:
            for status in self.sse_publisher.get_last_status_snapshot():
                yield _sse_message(status)

            while True:
                try:
                    data = client_queue.get(timeout=CLIENT_POLL_TIMEOUT)
                    yield _sse_message(data)
                except Empty:
                    yield _sse_message(HEARTBEAT)
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
