import time
from multiprocessing import Event, Value

from storage.db_interface_backend import BackEndDbInterface
from test.acceptance.base import TestAcceptanceBase


class TestAcceptanceBaseFullStart(TestAcceptanceBase):

    NUMBER_OF_FILES_TO_ANALYZE = 4
    NUMBER_OF_PLUGINS = 2

    def setUp(self):
        super().setUp()
        self.analysis_finished_event = Event()
        self.compare_finished_event = Event()
        self.elements_finished_analyzing = Value('i', 0)
        self.db_backend_service = BackEndDbInterface(config=self.config)
        self._start_backend(post_analysis=self._analysis_callback, compare_callback=self._compare_callback)
        time.sleep(2)  # wait for systems to start

    def tearDown(self):
        self._stop_backend()
        self.db_backend_service.shutdown()
        super().tearDown()

    def _analysis_callback(self, fo):
        self.db_backend_service.add_object(fo)
        self.elements_finished_analyzing.value += 1
        if self.elements_finished_analyzing.value == self.NUMBER_OF_FILES_TO_ANALYZE * self.NUMBER_OF_PLUGINS:
            self.analysis_finished_event.set()

    def _compare_callback(self):
        self.compare_finished_event.set()
