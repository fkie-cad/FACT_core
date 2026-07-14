from __future__ import annotations

import time
from math import ceil
from pickle import dumps, loads
from queue import Empty
from random import randint
from typing import Any

from redis import Redis
from redis.backoff import ExponentialBackoff
from redis.connection import ConnectionPool
from redis.retry import Retry

import config

REDIS_MAX_VALUE_SIZE = 512_000_000  # 512 MB (not to be confused with 512 MiB)
CHUNK_MAGIC = b'$CHUNKED$'
SEPARATOR = '#'


class RedisInterface:
    def __init__(self, chunk_size: int = REDIS_MAX_VALUE_SIZE):
        self.chunk_size = chunk_size
        redis_db = config.common.redis.fact_db
        redis_host = config.common.redis.host
        redis_port = config.common.redis.port
        redis_pw = config.common.redis.password

        pool = ConnectionPool(
            host=redis_host,
            port=redis_port,
            db=redis_db,
            password=redis_pw,
            max_connections=200,
            socket_connect_timeout=5,
            socket_keepalive=True,
            retry_on_timeout=True,
        )
        retry = Retry(ExponentialBackoff(), 3)
        self.redis = Redis(connection_pool=pool, retry=retry)

    def set(self, key: str, value: Any) -> None:  # noqa: ANN401
        self.redis.set(key, self._split_if_necessary(dumps(value)))

    def get(self, key: str, delete: bool = True) -> Any:  # noqa: ANN401
        value = self._redis_pop(key) if delete else self.redis.get(key)
        return self._combine_if_split(value, delete=delete)

    def queue_put(self, key: str, value: Any) -> None:  # noqa: ANN401
        self.redis.rpush(key, self._split_if_necessary(dumps(value)))

    def queue_get(self, key: str) -> Any:  # noqa: ANN401
        return self._combine_if_split(self.redis.lpop(key))

    def queue_get_blocking(self, key: str, timeout: int) -> Any:
        result = self.redis.blpop([key], timeout=timeout)
        if result is None:
            return None
        _, value = result
        return self._combine_if_split(value)

    def _split_if_necessary(self, value: bytes) -> str | bytes:
        return self._store_chunks(value) if len(value) > self.chunk_size else value

    def _store_chunks(self, value: Any) -> str:  # noqa: ANN401
        meta_key = CHUNK_MAGIC.decode()
        for index in range(ceil(len(value) / self.chunk_size)):
            key = self._get_new_chunk_key()
            chunk = value[self.chunk_size * index : self.chunk_size * (index + 1)]
            self.redis.set(key, chunk)
            meta_key += SEPARATOR + key
        return meta_key

    def _get_new_chunk_key(self) -> str:
        while True:
            key = f'chunk_{randint(0, 9999)}'  # noqa: S311
            if not self.redis.exists(key):
                return key

    def _combine_if_split(self, value: bytes | None, delete: bool = True) -> Any:  # noqa: ANN401
        if value is None:
            return None
        if value.startswith(CHUNK_MAGIC):
            value = self._combine_chunks(value.decode(), delete=delete)
        return loads(value)  # noqa: S301

    def _combine_chunks(self, meta_key: str, delete: bool) -> bytes:
        return b''.join(
            [
                self._redis_pop(chunk_key) if delete else self.redis.get(chunk_key)
                for chunk_key in meta_key.split(SEPARATOR)[1:]
            ]
        )

    def _redis_pop(self, key: str) -> bytes | None:
        pipeline = self.redis.pipeline()
        pipeline.get(key)
        pipeline.delete(key)
        value, _ = pipeline.execute()
        return value


class RQueue:
    """Quacks like a mp.Queue"""

    def __init__(self, redis_interface: RedisInterface, key: str):
        self.redis_interface = redis_interface
        self.key = key

    def put(self, value: Any) -> None:
        self.redis_interface.queue_put(self.key, value)

    def get(self, timeout: int) -> Any:
        value = self.redis_interface.queue_get_blocking(self.key, timeout)
        if value is None:
            raise Empty
        return value

    def qsize(self) -> int:
        return self.redis_interface.redis.llen(self.key)

    def close(self) -> None:
        pass
