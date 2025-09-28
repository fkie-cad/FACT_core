from multiprocessing import Queue
from time import sleep

import pytest

from intercom.back_end_binding import InterComBackEndBinding
from intercom.common_redis_binding import InterComListener
from intercom.front_end_binding import InterComFrontEndBinding

# This number must be changed, whenever a listener is added or removed
NUMBER_OF_LISTENERS = 14


class ServiceMock:
    def __init__(self, test_queue):
        self.test_queue = test_queue

    def add_task(self, fo):
        self.test_queue.put(fo)

    def get_binary_and_name(self, uid):
        pass


class TestListener(InterComListener):
    CONNECTION_TYPE = 'test_task'


class AnalysisServiceMock:
    def update_analysis_of_object_and_children(self, fo):
        pass

    def get_plugin_dict(self):
        return {}

    def update_analysis_of_single_object(self, fw):
        pass


@pytest.fixture(name='intercom')
def get_intercom_for_testing():
    test_queue = Queue()
    interface = InterComBackEndBinding(
        analysis_service=AnalysisServiceMock(),
        comparison_service=ServiceMock(test_queue),
        unpacking_service=ServiceMock(test_queue),
    )
    interface.WAIT_TIME = 2
    yield interface
    interface.shutdown()
    test_queue.close()


def test_backend_worker(intercom):
    test_queue = Queue()
    service = ServiceMock(test_queue)
    listener = TestListener(service.add_task)
    intercom.listeners.append(listener)
    intercom.start()
    intercom_frontend = InterComFrontEndBinding()

    test_task = 'test_task'
    intercom_frontend._add_to_redis_queue(listener.CONNECTION_TYPE, test_task)
    result = test_queue.get(timeout=5)
    assert result == test_task, 'task not received correctly'


def test_all_listeners_started(intercom):
    intercom.start()
    assert len(intercom.listeners) == NUMBER_OF_LISTENERS, 'Not all listeners started'
    sleep(0.5)
    assert all(listener.process is not None for listener in intercom.listeners)
