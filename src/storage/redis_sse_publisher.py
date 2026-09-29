from __future__ import annotations

import json
import logging
import os
import threading
from contextlib import suppress
from queue import Empty, Full, Queue
from typing import TYPE_CHECKING

from storage.redis_interface import get_redis_from_cfg
from storage.redis_status_interface import COMPONENT_STATUS_REDIS_KEYS, PUBSUB_CHANNEL, RedisStatusInterface

if TYPE_CHECKING:
    from redis import Redis

UPDATE_INTERVAL = 1
INITIAL_RECONNECT_BACKOFF = 1
MAX_RECONNECT_BACKOFF = 30
ANALYSIS_STATUS_KEY = 'current_analyses'


class RedisSSEPublisher:
    def __init__(
        self,
        redis_client: Redis | None = None,
        status_interface: RedisStatusInterface | None = None,
        *,
        start_listener: bool = True,
    ):
        self.redis = redis_client or get_redis_from_cfg()
        self.status_interface = status_interface or RedisStatusInterface()

        self.subscribers: set[Queue] = set()
        self.pubsub = None
        self._lock = threading.Lock()
        self.last_status: dict[str, str] = {}
        self._should_stop = threading.Event()
        self.proc: threading.Thread | None = None
        self._cleanup_done = False
        self._listener_stopped = threading.Event()

        if start_listener:
            self._start_redis_listener()

    def _start_redis_listener(self) -> None:
        self.proc = threading.Thread(target=self._redis_listener, daemon=True)
        self.proc.start()

    def _redis_listener(self) -> None:
        logging.debug(f'[system health SSE]: started listener thread (PID={os.getpid()}, TID={threading.get_ident()})')
        backoff = INITIAL_RECONNECT_BACKOFF
        while not self._should_stop.is_set():
            try:
                self.pubsub = self.redis.pubsub()
                self.pubsub.subscribe(PUBSUB_CHANNEL)
                self._init_snapshot()
                backoff = INITIAL_RECONNECT_BACKOFF
                while not self._should_stop.is_set():
                    message = self.pubsub.get_message(timeout=UPDATE_INTERVAL)
                    if message and message['type'] == 'message':
                        self._handle_message(message)
            except ValueError:
                pass  # pubsub closed (shutdown)
            except Exception as e:
                if not self._should_stop.is_set():
                    logging.warning(f'[system health SSE]: listener error: {e}; reconnecting in {backoff}s')
            try:
                if self.pubsub:
                    self.pubsub.close()
            except Exception:
                logging.debug(f'[system health SSE]: error closing pubsub (PID={os.getpid()})')
            self.pubsub = None
            if not self._should_stop.is_set():
                self._should_stop.wait(backoff)  # wakes immediately on shutdown
                backoff = min(backoff * 2, MAX_RECONNECT_BACKOFF)
        self._listener_stopped.set()
        logging.debug(f'[system health SSE]: stopped listener thread (PID={os.getpid()}, TID={threading.get_ident()})')

    def _init_snapshot(self) -> None:
        """
        Initialize the snapshot with the current state from Redis. Otherwise, clients connecting to a freshly started
        worker would not get any data until the next update is published.
        """
        statuses = [self.status_interface.get_component_status(component) for component in COMPONENT_STATUS_REDIS_KEYS]
        statuses.append(self.status_interface.get_analysis_status())
        with self._lock:
            for status in statuses:
                if status:
                    self.last_status[_get_status_key(status)] = json.dumps(status, sort_keys=True)

    def _handle_message(self, message: dict) -> None:
        try:
            data = json.loads(message['data'].decode())
        except json.JSONDecodeError:
            logging.error(f'[system health SSE]: Error parsing JSON in message: {message}')
            return
        key = _get_status_key(data)
        json_data = json.dumps(data, sort_keys=True)

        with self._lock:
            if json_data == self.last_status.get(key):
                return  # if the data did not change, we don't send an update
            self.last_status[key] = json_data
            for queue in self.subscribers:
                try:
                    queue.put_nowait(json_data)
                except Full:
                    # drop the oldest pending update so the client catches up to the latest state
                    # (the client may have emptied the queue in the meantime -> Empty is no problem)
                    with suppress(Empty):
                        queue.get_nowait()
                    # can't be full again: queues are only filled while holding the lock
                    queue.put_nowait(json_data)

    def get_last_status_snapshot(self) -> list[str]:
        with self._lock:
            return list(self.last_status.values())

    def add_subscriber(self) -> Queue:
        subscriber_queue: Queue = Queue(maxsize=100)
        logging.debug(f'[system health SSE]: adding subscriber (ID={id(subscriber_queue)}, PID={os.getpid()})')
        with self._lock:
            self.subscribers.add(subscriber_queue)
        return subscriber_queue

    def remove_subscriber(self, subscriber_queue: Queue) -> None:
        logging.debug(f'[system health SSE]: removing subscriber (ID={id(subscriber_queue)}, PID={os.getpid()})')
        with self._lock:
            self.subscribers.discard(subscriber_queue)

    def shutdown(self) -> None:
        self._should_stop.set()
        self._stop_subscribers()
        if self.proc is not None:
            if not self._listener_stopped.wait(timeout=UPDATE_INTERVAL + 0.1):
                logging.warning('[system health SSE]: listener did not stop in time')
            self.proc.join(timeout=2)
        self._cleanup()

    def _stop_subscribers(self) -> None:
        # a `None` in the queue signals the event generator to end the stream
        with self._lock:
            for queue in self.subscribers:
                with suppress(Empty):
                    queue.get_nowait()  # make room in case the queue is full
                queue.put_nowait(None)

    def _cleanup(self) -> None:
        if self._cleanup_done:
            return
        logging.debug(f'[system health SSE]: Stopping publisher... (PID={os.getpid()})')
        self._cleanup_done = True
        try:
            if self.pubsub:
                self.pubsub.unsubscribe()
                self.pubsub.close()
                self.pubsub = None
        except Exception as e:
            logging.exception(f'[system health SSE]: Error during cleanup: {e}')


def _get_status_key(status: dict) -> str:
    return status.get('name', ANALYSIS_STATUS_KEY)
