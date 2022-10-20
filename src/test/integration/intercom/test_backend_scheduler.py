import gc
from multiprocessing import Queue, Value
from tempfile import TemporaryDirectory
from time import sleep

import pytest

from intercom.back_end_binding import InterComBackEndBinding
from test.common_helper import get_config_for_testing  # pylint: disable=wrong-import-order

# This number must be changed, whenever a listener is added or removed
NUMBER_OF_LISTENERS = 11


class ServiceMock:
    def __init__(self, test_queue):
        self.test_queue = test_queue

    def add_task(self, fo):
        self.test_queue.put(fo)

    def get_binary_and_name(self, uid):
        pass


class CommunicationBackendMock:

    counter = Value('i', 0)

    def __init__(self, config=None):
        pass

    def get_next_task(self):
        self.counter.value += 1
        return 'test_task' if self.counter.value < 2 else None

    def shutdown(self):
        pass


class AnalysisServiceMock:
    def __init__(self, config=None):
        pass

    def update_analysis_of_object_and_children(self, fo):
        pass

    def get_plugin_dict(self):  # pylint: disable=no-self-use
        return {}

    def update_analysis_of_single_object(self, fw):
        pass


@pytest.fixture(name='intercom')
def get_intercom_for_testing():
    with TemporaryDirectory(prefix='fact_test_') as tmp_dir:
        config = get_config_for_testing(tmp_dir)
        test_queue = Queue()
        interface = InterComBackEndBinding(
            config=config,
            testing=True,
            analysis_service=AnalysisServiceMock(),
            compare_service=ServiceMock(test_queue),
            unpacking_service=ServiceMock(test_queue),
        )
        interface.WAIT_TIME = 2
        yield interface
        interface.shutdown()
        test_queue.close()
    gc.collect()


def test_backend_worker(intercom):
    test_queue = Queue()
    service = ServiceMock(test_queue)
    intercom._start_listener(CommunicationBackendMock, service.add_task)  # pylint: disable=protected-access
    result = test_queue.get(timeout=5)
    assert result == 'test_task', 'task not received correctly'


def test_all_listeners_started(intercom):
    intercom.start_listeners()
    sleep(2)
    assert len(intercom.process_list) == NUMBER_OF_LISTENERS, 'Not all listeners started'
