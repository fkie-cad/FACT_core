from __future__ import annotations

import json
import logging
import os
import threading
from queue import Queue
from typing import TYPE_CHECKING

from storage.redis_interface import get_redis_from_cfg
from storage.redis_status_interface import PUBSUB_CHANNEL

if TYPE_CHECKING:
    from redis import Redis

UPDATE_INTERVAL = 1


class RedisSSEPublisher:
    def __init__(self, redis_client: Redis | None = None):
        self.redis = redis_client or get_redis_from_cfg()

        self.subscribers = {}
        self.pubsub = None
        self._lock = threading.Lock()
        self.last_status = {}
        self._should_stop = threading.Event()
        self.proc = None
        self._cleanup_done = False
        self._listener_stopped = threading.Event()

        self._start_redis_listener()

    def _start_redis_listener(self):
        self.proc = threading.Thread(target=self._redis_listener, daemon=True)
        self.proc.start()

    def _redis_listener(self):
        logging.debug(f'[system health SSE]: started listener thread (PID={os.getpid()}, TID={threading.get_ident()})')
        self.pubsub = self.redis.pubsub()
        self.pubsub.subscribe(PUBSUB_CHANNEL)
        try:
            while not self._should_stop.is_set():
                message = self.pubsub.get_message(timeout=UPDATE_INTERVAL)
                if message and message['type'] == 'message':
                    self._handle_message(message)
        except ValueError:
            pass  # redis pubsub closed (probably because of shutdown)
        self._listener_stopped.set()
        logging.debug(f'[system health SSE]: stopped listener thread (PID={os.getpid()}, TID={threading.get_ident()})')

    def _handle_message(self, message):
        try:
            data = json.loads(message['data'].decode())
            key = data.get('name', 'current_analyses')
            old_data = self.last_status.get(key)
            json_data = json.dumps(data, sort_keys=True)
            if json_data != old_data:
                # if the data did not change, we don't send an update
                self.last_status[key] = json_data
                if self.subscribers:
                    self._broadcast_to_sse_clients(data)
        except json.JSONDecodeError:
            logging.error(f'[system health SSE]: Error parsing JSON in message: {message}')

    def _broadcast_to_sse_clients(self, data):
        with self._lock:
            for queue in list(self.subscribers.values()):
                try:
                    queue.put(data, block=False)
                except Exception as e:
                    logging.debug(f'[system health SSE]: Error during broadcast: {e}')
                    self.remove_subscriber(queue)

    def add_subscriber(self):
        subscriber_queue = Queue(maxsize=100)
        logging.info(f'[system health SSE]: adding subscriber (ID={hash(subscriber_queue)}, PID={os.getpid()})')
        with self._lock:
            self.subscribers[hash(subscriber_queue)] = subscriber_queue
        return subscriber_queue

    def remove_subscriber(self, subscriber_queue):
        logging.info(f'[system health SSE]: removing subscriber (ID={hash(subscriber_queue)}, PID={os.getpid()})')
        with self._lock:
            self.subscribers.pop(hash(subscriber_queue))

    def shutdown(self):
        self._should_stop.set()
        self._listener_stopped.wait(timeout=UPDATE_INTERVAL + 0.1)  # give listener thread time to stop
        self._cleanup()

    def _cleanup(self):
        if self._cleanup_done:
            return
        logging.info(f'[system health SSE]: Stopping publisher... (PID={os.getpid()})')
        self._cleanup_done = True
        try:
            if self.pubsub:
                self.pubsub.unsubscribe()
                self.pubsub.close()
                self.pubsub = None
        except Exception as e:
            logging.exception(f'[system health SSE]: Error during cleanup: {e}')
