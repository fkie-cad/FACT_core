import gc
import unittest
from multiprocessing import Queue, Value
from tempfile import TemporaryDirectory
from time import sleep

from intercom.back_end_binding import InterComBackEndBinding
from storage.MongoMgr import MongoMgr
from test.common_helper import get_config_for_testing

TMP_DIR = TemporaryDirectory(prefix='fact_test_')


# This number must be changed, whenever a listener is added or removed
NUMBER_OF_LISTENERS = 9


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


class TestInterComBackEndScheduler(unittest.TestCase):

    def setUp(self):
        config = get_config_for_testing(TMP_DIR)
        self.test_queue = Queue()
        self.interface = InterComBackEndBinding(
            config=config, testing=True, analysis_service=AnalysisServiceMock(), compare_service=ServiceMock(self.test_queue), unpacking_service=ServiceMock(self.test_queue)
        )
        self.interface.WAIT_TIME = 2
        self.db = MongoMgr(config=config)

    def tearDown(self):
        self.interface.shutdown()
        self.test_queue.close()
        self.db.shutdown()
        TMP_DIR.cleanup()
        gc.collect()

    def test_backend_worker(self):
        service = ServiceMock(self.test_queue)
        self.interface._start_listener(CommunicationBackendMock, service.add_task)  # pylint: disable=protected-access
        result = self.test_queue.get(timeout=5)
        self.assertEqual(result, 'test_task', 'task not received correctly')

    def test_all_listeners_started(self):
        self.interface.startup()
        sleep(2)
        self.assertEqual(len(self.interface.process_list), NUMBER_OF_LISTENERS, 'Not all listeners started')
