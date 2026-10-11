import pytest

from storage.redis_status_interface import RedisStatusInterface

EMPTY_RESULT = {'current_analyses': {}, 'recently_finished_analyses': {}}
TEST_RESULT = {'current_analyses': {'foo': {}}, 'recently_finished_analyses': {'bar': {}}}


@pytest.fixture
def status_interface():
    interface = RedisStatusInterface()
    yield interface
    interface.redis.redis.flushdb()


def test_analysis_status(status_interface):
    assert status_interface.get_analysis_status() == EMPTY_RESULT

    status_interface.set_analysis_status(TEST_RESULT)
    assert status_interface.get_analysis_status() == TEST_RESULT


def test_component_status(status_interface):
    assert status_interface.get_component_status('frontend') is None

    status_interface.set_component_status('frontend', TEST_RESULT)
    assert status_interface.get_component_status('frontend') == TEST_RESULT
