# pylint: disable=redefined-outer-name,wrong-import-order

from os import urandom

import pytest

from storage.redis_interface import CHUNK_MAGIC, RedisInterface

CHUNK_SIZE = 1_000


@pytest.fixture(scope='function')
def redis(cfg_tuple):
    _, configparser_cfg = cfg_tuple
    interface = RedisInterface(config=configparser_cfg, chunk_size=CHUNK_SIZE)
    try:
        yield interface
    finally:
        interface.redis.flushdb()


def test_set_and_get(redis):
    value = {'a': 1, 'b': '2', 'c': b'3'}
    redis.set('key', value)
    assert redis.redis.get('key') is not None
    assert redis.get('key', delete=False) == value
    assert redis.redis.get('key') is not None
    assert redis.get('key', delete=True) == value
    assert redis.redis.get('key') is None


def test_set_and_get_chunked(redis):
    value = urandom(int(CHUNK_SIZE * 2.5))
    redis.set('key', value)
    assert redis.redis.get('key').startswith(CHUNK_MAGIC)
    assert redis.get('key', delete=False) == value
    assert redis.get('key', delete=True) == value
    assert redis.get('key') is None


def test_queue_put_and_get(redis):
    values = [1, '2', b'3']
    for value in values:
        redis.queue_put('key', value)
    assert redis.redis.llen('key') == 3  # redis list length
    for value in values:
        assert redis.queue_get('key') == value
    assert redis.queue_get('key') is None


def test_queue_chunked(redis):
    value = urandom(int(CHUNK_SIZE * 2.5))
    redis.queue_put('key', value)
    list_item = redis.redis.lrange('key', 0, 0)[0]
    assert list_item.startswith(CHUNK_MAGIC)
    assert redis.queue_get('key') == value
    assert redis.queue_get('key') is None
