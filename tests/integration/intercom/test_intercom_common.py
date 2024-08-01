import os

import pytest

from fact.helperFunctions.data_conversion import convert_str_to_bool
from fact.intercom.common_redis_binding import InterComListener
from fact.storage.redis_interface import REDIS_MAX_VALUE_SIZE


@pytest.fixture
def listener():
    generic_listener = InterComListener()
    try:
        yield generic_listener
    finally:
        generic_listener.redis.redis.flushdb()


def check_file(binary, generic_listener):
    generic_listener.redis.queue_put(generic_listener.CONNECTION_TYPE, (binary, 'task_id'))
    task = generic_listener.get_next_task()
    assert task == binary
    another_task = generic_listener.get_next_task()
    assert another_task is None, 'task not deleted'


def test_small_file(listener):
    check_file(b'this is a test', listener)


@pytest.mark.skipif(not convert_str_to_bool(os.environ.get('RUN_EXPENSIVE_TESTS', '0')), reason='should not run on CI')
def test_big_file(listener):
    large_test_data = b'\x00' * int(REDIS_MAX_VALUE_SIZE * 1.2)
    check_file(large_test_data, listener)
