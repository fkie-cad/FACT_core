import pytest

from storage.rest_status_interface import RestStatusInterface


EMPTY_RESULT = {'current_analyses': {}, 'recently_finished_analyses': {}}
TEST_RESULT = {'current_analyses': {'foo': {}}, 'recently_finished_analyses': {'bar': {}}}


@pytest.fixture
def status_interface():
    interface = RestStatusInterface()
    yield interface
    interface.redis.redis.flushdb()


def test_rest_status_interface(status_interface):
    assert status_interface.get_analysis_status() == EMPTY_RESULT

    status_interface.set_analysis_status(TEST_RESULT)
    assert status_interface.get_analysis_status() == TEST_RESULT
