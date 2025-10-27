from __future__ import annotations

import json
import logging
from queue import Empty
from typing import Iterator

from flask import Response

from storage.redis_sse_publisher import RedisSSEPublisher
from web_interface.components.component_base import GET, AppRoute, ComponentBase
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES

HEARTBEAT = json.dumps({'type': 'heartbeat'})


class SseRoutes(ComponentBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.sse_publisher = RedisSSEPublisher()

    @roles_accepted(*PRIVILEGES['status'])
    @AppRoute('/status-stream', GET)
    def status_stream(self):
        return Response(
            self._event_generator(),
            mimetype='text/event-stream',
            headers={'Cache-Control': 'no-cache', 'Connection': 'keep-alive', 'Access-Control-Allow-Origin': '*'},
        )

    def _event_generator(self) -> Iterator[str]:
        logging.info('Received subscription request')
        client_queue = self.sse_publisher.add_subscriber()

        try:
            if self.sse_publisher.last_status:
                for status in self.sse_publisher.last_status.values():
                    yield _sse_message(status)

            while True:
                try:
                    data = client_queue.get(timeout=30)
                    yield _sse_message(data)
                except Empty:
                    yield _sse_message(HEARTBEAT)
        except GeneratorExit:
            pass
        finally:
            self.sse_publisher.remove_subscriber(client_queue)

    def shutdown(self):
        self.sse_publisher.shutdown()


def _sse_message(data: dict | str) -> str:
    if not isinstance(data, str):
        data = json.dumps(data)
    return f'data: {data}\n\n'
