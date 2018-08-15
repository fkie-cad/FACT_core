import gc
from multiprocessing import Queue
import unittest
from unittest.mock import patch

from helperFunctions.fileSystem import get_test_data_dir
from objects.firmware import Firmware
from scheduler.Analysis import AnalysisScheduler
from scheduler.Unpacking import UnpackingScheduler
from test.common_helper import DatabaseMock, fake_exit
from test.integration.common import initialize_config, MockDbInterface, MockFSOrganizer


class TestFileAddition(unittest.TestCase):
    @patch('unpacker.unpack.FS_Organizer', MockFSOrganizer)
    def setUp(self):
        self.mocked_interface = DatabaseMock()
        self.enter_patch = unittest.mock.patch(target='helperFunctions.web_interface.ConnectTo.__enter__', new=lambda _: self.mocked_interface)
        self.enter_patch.start()
        self.exit_patch = unittest.mock.patch(target='helperFunctions.web_interface.ConnectTo.__exit__', new=fake_exit)
        self.exit_patch.start()

        self._config = initialize_config(None)
        self._tmp_queue = Queue()

        self._analysis_scheduler = AnalysisScheduler(config=self._config, pre_analysis=lambda *_: None, post_analysis=self._dummy_callback, db_interface=MockDbInterface(None))
        self._unpack_scheduler = UnpackingScheduler(config=self._config, post_unpack=self._analysis_scheduler.add_task)

    def tearDown(self):
        self._unpack_scheduler.shutdown()
        self._analysis_scheduler.shutdown()
        self._tmp_queue.close()

        self.enter_patch.stop()
        self.exit_patch.stop()
        self.mocked_interface.shutdown()
        gc.collect()

    def test_unpack_and_analyse(self):
        test_fw = Firmware(file_path='{}/container/test.zip'.format(get_test_data_dir()))

        self._unpack_scheduler.add_task(test_fw)

        for _ in range(4 * 2):  # container with 3 included files times 2 mandatory plugins run
            processed_container = self._tmp_queue.get(timeout=10)

        self.assertGreaterEqual(len(processed_container.processed_analysis), 3, 'at least one analysis not done')

    def _dummy_callback(self, fw, _):
        self._tmp_queue.put(fw)
