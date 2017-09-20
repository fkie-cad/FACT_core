import unittest
from multiprocessing import Queue
from unittest.mock import patch

from helperFunctions.fileSystem import get_test_data_dir
from objects.firmware import Firmware
from scheduler.Analysis import AnalysisScheduler
from scheduler.Unpacking import UnpackingScheduler
from test.integration.common import initialize_config, MockDbInterface, MockFSOrganizer


class TestFileAddition(unittest.TestCase):
    @patch('unpacker.unpack.FS_Organizer', MockFSOrganizer)
    def setUp(self):
        self._config = initialize_config(None)
        self._tmp_queue = Queue()

        self._analysis_scheduler = AnalysisScheduler(config=self._config, post_analysis=self._dummy_callback, db_interface=MockDbInterface(None))
        self._unpack_scheduler = UnpackingScheduler(config=self._config, post_unpack=self._analysis_scheduler.add_task)

    def tearDown(self):
        self._unpack_scheduler.shutdown()
        self._analysis_scheduler.shutdown()
        self._tmp_queue.close()

    def test_unpack_and_analyse(self):
        test_fw = Firmware(file_path='{}/container/test.zip'.format(get_test_data_dir()))

        self._unpack_scheduler.add_task(test_fw)

        processed_container = self._tmp_queue.get(timeout=10)

        self.assertGreaterEqual(len(processed_container.processed_analysis), 3, 'at least one analysis not done')

    def _dummy_callback(self, fw):
        self._tmp_queue.put(fw)
