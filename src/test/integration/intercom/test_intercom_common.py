import pickle

import pytest

from intercom.common_redis_binding import InterComListener
from test.common_helper import get_config_for_testing

REDIS_MAX_VALUE_SIZE = 512_000_000


@pytest.fixture(scope='function')
def listener():
    generic_listener = InterComListener(config=get_config_for_testing())
    try:
        yield generic_listener
    finally:
        generic_listener.redis.flushdb()


def check_file(binary, generic_listener):
    generic_listener.redis.rpush(generic_listener.CONNECTION_TYPE, pickle.dumps((binary, 'task_id')))
    task = generic_listener.get_next_task()
    assert task == binary
    another_task = generic_listener.get_next_task()
    assert another_task is None, 'task not deleted'


def test_small_file(listener):
    check_file(b'this is a test', listener)


# ToDo: fix intercom for larger values
@pytest.mark.skip(reason='fixme plz')
def test_big_file(listener):
    large_test_data = b'\x00' * (REDIS_MAX_VALUE_SIZE + 1024)
    check_file(large_test_data, listener)
