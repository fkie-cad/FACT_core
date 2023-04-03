import gc
from configparser import ConfigParser
from multiprocessing import Event, Queue
from tempfile import TemporaryDirectory
from time import sleep
from unittest import TestCase
from unittest.mock import patch

import pytest

from objects.firmware import Firmware
from scheduler.unpacking_scheduler import UnpackingScheduler
from storage.unpacking_locks import UnpackingLockManager
from test.common_helper import get_test_data_dir


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
        included_files = [
            'ab4153d747f530f9bc3a4b71907386f50472ea5ae975c61c0bacd918f1388d4b_227',
            'faa11db49f32a90b51dfc3f0254f9fd7a7b46d0b570abd47e1943b86d554447a_28',
        ]
        self.scheduler.add_task(test_fw)
        extracted_files = {}
        for _ in range(3):
            file = self.tmp_queue.get(timeout=5)
            extracted_files[file.uid] = file

        assert test_fw.uid in extracted_files
        assert len(extracted_files[test_fw.uid].files_included) == 2, 'not all children of fw found'
        assert (
            included_files[0] in extracted_files[test_fw.uid].files_included
        ), 'included container not extracted. Unpacker tar.gz module broken?'
        assert all(f in extracted_files for f in included_files)
        assert len(extracted_files[included_files[0]].files_included) == 1

    def test_get_combined_analysis_workload(self):
        self._start_scheduler()
        result = self.scheduler._get_combined_analysis_workload()  # pylint: disable=protected-access
        assert result == 3, 'workload calculation not correct'

    @pytest.mark.cfg_defaults(
        {
            'expert-settings': {
                'unpack-throttle-limit': -1,
            }
        }
    )
    def test_throttle(self):
        with patch(target='scheduler.unpacking_scheduler.sleep', new=self._trigger_sleep):
            self._start_scheduler()
            self.sleep_event.wait(timeout=10)

        assert self.scheduler.throttle_condition.value == 1, 'unpack load throttle not functional'

    def _start_scheduler(self):
        self.scheduler = UnpackingScheduler(
            post_unpack=self._mock_callback,
            analysis_workload=lambda: 3,
            unpacking_locks=UnpackingLockManager(),
        )
        self.scheduler.start()

    def _mock_callback(self, fw):
        self.tmp_queue.put(fw)

    def _trigger_sleep(self, seconds: int) -> None:
        self.sleep_event.set()

        sleep(seconds)
