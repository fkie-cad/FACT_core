import gc
from configparser import ConfigParser
from multiprocessing import Event, Queue
from tempfile import TemporaryDirectory
from time import sleep
from unittest import TestCase
from unittest.mock import patch

from objects.firmware import Firmware
from scheduler.unpacking_scheduler import UnpackingScheduler
from storage.unpacking_locks import UnpackingLockManager
from test.common_helper import create_docker_mount_base_dir, get_test_data_dir


class TestUnpackScheduler(TestCase):

    def setUp(self):
        self.tmp_dir = TemporaryDirectory()
        self.config = ConfigParser()
        self.config.add_section('unpack')
        self.config.set('unpack', 'threads', '2')
        self.config.set('unpack', 'max-depth', '3')
        self.config.set('unpack', 'whitelist', '')
        self.config.add_section('expert-settings')
        self.config.set('expert-settings', 'block-delay', '1')
        self.config.set('expert-settings', 'unpack-throttle-limit', '10')
        self.config.add_section('data-storage')
        self.config.set('data-storage', 'firmware-file-storage-directory', self.tmp_dir.name)
        self.docker_mount_base_dir = create_docker_mount_base_dir()
        self.config.set('data-storage', 'docker-mount-base-dir', str(self.docker_mount_base_dir))
        self.tmp_queue = Queue()
        self.scheduler = None

        self.sleep_event = Event()

    def tearDown(self):
        if self.scheduler:
            self.scheduler.shutdown()
        self.tmp_dir.cleanup()
        self.tmp_queue.close()
        gc.collect()

    def test_unpack_a_container_including_another_container(self):
        self._start_scheduler()
        test_fw = Firmware(file_path=f'{get_test_data_dir()}/container/test_zip.tar.gz')
        self.scheduler.add_task(test_fw)
        outer_container = self.tmp_queue.get(timeout=5)
        self.assertEqual(len(outer_container.files_included), 2, 'not all children of root found')
        self.assertIn('ab4153d747f530f9bc3a4b71907386f50472ea5ae975c61c0bacd918f1388d4b_227', outer_container.files_included, 'included container not extracted. Unpacker tar.gz modul broken?')
        included_files = [self.tmp_queue.get(timeout=5), self.tmp_queue.get(timeout=5)]
        for item in included_files:
            if item.uid == 'ab4153d747f530f9bc3a4b71907386f50472ea5ae975c61c0bacd918f1388d4b_227':
                self.assertEqual(len(item.files_included), 1, 'number of files in included container not correct')
            else:
                self.assertEqual(item.uid, 'faa11db49f32a90b51dfc3f0254f9fd7a7b46d0b570abd47e1943b86d554447a_28', 'none container file not rescheduled')

    def test_get_combined_analysis_workload(self):
        self._start_scheduler()
        result = self.scheduler._get_combined_analysis_workload()  # pylint: disable=protected-access
        self.assertEqual(result, 3, 'workload calculation not correct')

    def test_throttle(self):
        with patch(target='scheduler.unpacking_scheduler.sleep', new=self._trigger_sleep):
            self.config.set('expert-settings', 'unpack-throttle-limit', '-1')
            self._start_scheduler()
            self.sleep_event.wait(timeout=10)

        assert self.scheduler.throttle_condition.value == 1, 'unpack load throttle not functional'

    def _start_scheduler(self):
        self.scheduler = UnpackingScheduler(
            post_unpack=self._mock_callback,
            analysis_workload=lambda: 3,
            unpacking_locks=UnpackingLockManager()
        )

    def _mock_callback(self, fw):
        self.tmp_queue.put(fw)

    def _trigger_sleep(self, seconds: int) -> None:
        self.sleep_event.set()

        sleep(seconds)
