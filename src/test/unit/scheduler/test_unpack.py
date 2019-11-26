from configparser import ConfigParser
import gc
from multiprocessing import Queue
from tempfile import TemporaryDirectory
from time import sleep
import unittest

from helperFunctions.fileSystem import get_test_data_dir
from objects.firmware import Firmware
from scheduler.Unpacking import UnpackingScheduler
from test.common_helper import DatabaseMock


class TestUnpackScheduler(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = TemporaryDirectory()
        self.config = ConfigParser()
        self.config.add_section('unpack')
        self.config.set('unpack', 'threads', '2')
        self.config.set('unpack', 'max_depth', '3')
        self.config.set('unpack', 'whitelist', '')
        self.config.add_section('ExpertSettings')
        self.config.set('ExpertSettings', 'block_delay', '1')
        self.config.set('ExpertSettings', 'unpack_throttle_limit', '10')
        self.config.add_section('data_storage')
        self.config.set('data_storage', 'firmware_file_storage_directory', self.tmp_dir.name)
        self.tmp_queue = Queue()
        self.sched = None

    def tearDown(self):
        if self.sched:
            self.sched.shutdown()
        self.tmp_dir.cleanup()
        self.tmp_queue.close()
        gc.collect()

    def test_unpack_a_container_including_another_container(self):
        self._start_scheduler()
        test_fw = Firmware(file_path='{}/container/test_zip.tar.gz'.format(get_test_data_dir()))
        self.sched.add_task(test_fw)
        outer_container = self.tmp_queue.get(timeout=5)
        self.assertEqual(len(outer_container.files_included), 2, 'not all childs of root found')
        self.assertIn('ab4153d747f530f9bc3a4b71907386f50472ea5ae975c61c0bacd918f1388d4b_227', outer_container.files_included, 'included container not extracted. Unpacker tar.gz modul broken?')
        included_files = [self.tmp_queue.get(timeout=5)]
        included_files.append(self.tmp_queue.get(timeout=5))
        for item in included_files:
            if item.uid == 'ab4153d747f530f9bc3a4b71907386f50472ea5ae975c61c0bacd918f1388d4b_227':
                self.assertEqual(len(item.files_included), 1, 'number of files in included container not correct')
            else:
                self.assertEqual(item.uid, 'faa11db49f32a90b51dfc3f0254f9fd7a7b46d0b570abd47e1943b86d554447a_28', 'none container file not rescheduled')

    def test_get_combined_analysis_workload(self):
        self._start_scheduler()
        result = self.sched._get_combined_analysis_workload()
        self.assertEqual(result, 3, 'workload calculation not correct')

    def test_throttle(self):
        self.config.set('ExpertSettings', 'unpack_throttle_limit', '-1')
        self._start_scheduler()
        sleep(0.5)
        self.assertEqual(self.sched.throttle_condition.value, 1, 'throttle not functional')

    def _start_scheduler(self):
        self.sched = UnpackingScheduler(config=self.config, post_unpack=self._mock_callback, analysis_workload=self._mock_get_analysis_workload, db_interface=DatabaseMock())

    def _mock_callback(self, fw):
        self.tmp_queue.put(fw)

    @staticmethod
    def _mock_get_analysis_workload():
        return {'a': 1, 'b': 2}
