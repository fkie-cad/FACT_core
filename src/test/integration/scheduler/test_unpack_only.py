# pylint: disable=wrong-import-order,attribute-defined-outside-init
import gc
from multiprocessing import Queue

from objects.firmware import Firmware
from scheduler.unpacking_scheduler import UnpackingScheduler
from storage.unpacking_locks import UnpackingLockManager
from test.common_helper import get_test_data_dir
from test.integration.common import MockFSOrganizer, initialize_config


class TestFileAddition:
    def setup(self):
        self._config = initialize_config(tmp_dir=None)
        self._tmp_queue = Queue()
        unpacking_lock_manager = UnpackingLockManager()
        self._unpack_scheduler = UnpackingScheduler(
            post_unpack=self._dummy_callback, fs_organizer=MockFSOrganizer(),
            unpacking_locks=unpacking_lock_manager
        )

    def teardown(self):
        self._unpack_scheduler.shutdown()
        self._tmp_queue.close()
        gc.collect()

    def test_unpack_only(self):
        test_fw = Firmware(file_path=f'{get_test_data_dir()}/container/test.zip')

        self._unpack_scheduler.add_task(test_fw)

        processed_container = self._tmp_queue.get(timeout=5)

        assert len(processed_container.files_included) == 3, 'not all included files found'
        included_uids = {
            '289b5a050a83837f192d7129e4c4e02570b94b4924e50159fad5ed1067cfbfeb_20',
            'd558c9339cb967341d701e3184f863d3928973fccdc1d96042583730b5c7b76a_62',
            'faa11db49f32a90b51dfc3f0254f9fd7a7b46d0b570abd47e1943b86d554447a_28'
        }
        assert processed_container.files_included == included_uids, 'certain file missing after unpacking'

    def _dummy_callback(self, fw):
        self._tmp_queue.put(fw)
