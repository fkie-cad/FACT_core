from multiprocessing import Queue, Value
from time import sleep

import pytest

from intercom.back_end_binding import InterComBackEndBinding

# This number must be changed, whenever a listener is added or removed
NUMBER_OF_LISTENERS = 12


class ServiceMock:
    def __init__(self, test_queue):
        self.test_queue = test_queue

    def add_task(self, fo):
        self.test_queue.put(fo)

    def get_binary_and_name(self, uid):
        pass


class CommunicationBackendMock:
    counter = Value('i', 0)

    def __init__(self):
        pass

    def get_next_task(self):
        self.counter.value += 1
        return 'test_task' if self.counter.value < 2 else None  # noqa: PLR2004

    def shutdown(self):
        pass


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
        testing=True,
        analysis_service=AnalysisServiceMock(),
        compare_service=ServiceMock(test_queue),
        unpacking_service=ServiceMock(test_queue),
    )
    interface.WAIT_TIME = 2
    yield interface
    interface.shutdown()
    test_queue.close()


def test_backend_worker(intercom):
    test_queue = Queue()
    service = ServiceMock(test_queue)
    intercom._start_listener(CommunicationBackendMock, service.add_task)
    result = test_queue.get(timeout=5)
    assert result == 'test_task', 'task not received correctly'


def test_all_listeners_started(intercom):
    intercom.start()
    sleep(2)
    assert len(intercom.process_list) == NUMBER_OF_LISTENERS, 'Not all listeners started'
