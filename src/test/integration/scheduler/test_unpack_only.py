import gc
import unittest
from multiprocessing import Queue
from unittest.mock import patch

from objects.firmware import Firmware
from scheduler.Unpacking import UnpackingScheduler
from test.common_helper import DatabaseMock, get_test_data_dir
from test.integration.common import MockFSOrganizer, initialize_config


class TestFileAddition(unittest.TestCase):
    @patch('unpacker.unpack.FS_Organizer', MockFSOrganizer)
    def setUp(self):
        self._config = initialize_config(tmp_dir=None)
        self._tmp_queue = Queue()
        self._unpack_scheduler = UnpackingScheduler(config=self._config, post_unpack=self._dummy_callback, db_interface=DatabaseMock())

    def tearDown(self):
        self._unpack_scheduler.shutdown()
        self._tmp_queue.close()
        gc.collect()

    def test_unpack_only(self):
        test_fw = Firmware(file_path='{}/container/test.zip'.format(get_test_data_dir()))

        self._unpack_scheduler.add_task(test_fw)

        processed_container = self._tmp_queue.get(timeout=5)

        self.assertEqual(len(processed_container.files_included), 3, 'not all included files found')
        self.assertIn('faa11db49f32a90b51dfc3f0254f9fd7a7b46d0b570abd47e1943b86d554447a_28', processed_container.files_included, 'certain file missing after unpacking')

    def _dummy_callback(self, fw):
        self._tmp_queue.put(fw)
