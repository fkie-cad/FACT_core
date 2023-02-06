# pylint: disable=wrong-import-order,too-many-instance-attributes,attribute-defined-outside-init
import gc
from multiprocessing import Event, Value
from tempfile import TemporaryDirectory

from objects.firmware import Firmware
from scheduler.analysis import AnalysisScheduler
from scheduler.unpacking_scheduler import UnpackingScheduler
from storage.db_interface_backend import BackendDbInterface
from storage.unpacking_locks import UnpackingLockManager
from test.common_helper import get_test_data_dir


class TestTagPropagation:
    def setup(self):
        self._tmp_dir = TemporaryDirectory()  # pylint: disable=consider-using-with
        self.analysis_finished_event = Event()
        self.elements_finished_analyzing = Value('i', 0)
        self.uid_of_key_file = '530bf2f1203b789bfe054d3118ebd29a04013c587efd22235b3b9677cee21c0e_2048'

        self.backend_interface = BackendDbInterface()
        self.unpacking_lock_manager = UnpackingLockManager()

        self._analysis_scheduler = AnalysisScheduler(
            pre_analysis=self.backend_interface.add_object,
            post_analysis=self.count_analysis_finished_event,
            unpacking_locks=self.unpacking_lock_manager,
        )
        self._analysis_scheduler.start()
        self._unpack_scheduler = UnpackingScheduler(
            post_unpack=self._analysis_scheduler.start_analysis_of_object,
            unpacking_locks=self.unpacking_lock_manager,
        )
        self._unpack_scheduler.start()

    def count_analysis_finished_event(self, uid, plugin, analysis_result):
        self.elements_finished_analyzing.value += 1
        self.backend_interface.add_analysis(uid, plugin, analysis_result)
        if self.elements_finished_analyzing.value >= 15:  # 5 objects * 3 analyses = 15 calls
            self.analysis_finished_event.set()

    def teardown(self):
        self._unpack_scheduler.shutdown()
        self.unpacking_lock_manager.shutdown()
        self._analysis_scheduler.shutdown()

        self._tmp_dir.cleanup()
        gc.collect()

    def test_run_analysis_with_tag(self, db):  # pylint: disable=unused-argument
        test_fw = Firmware(file_path=f'{get_test_data_dir()}/container/with_key.7z')
        test_fw.version, test_fw.vendor, test_fw.device_name, test_fw.device_class = ['foo'] * 4
        test_fw.release_date = '2017-01-01'
        test_fw.scheduled_analysis = ['crypto_material']

        self._unpack_scheduler.add_task(test_fw)

        assert self.analysis_finished_event.wait(timeout=20)

        processed_fo = self.backend_interface.get_object(self.uid_of_key_file, analysis_filter=['crypto_material'])
        assert processed_fo.processed_analysis['crypto_material']['tags'], 'no tags set in analysis'

        processed_fw = self.backend_interface.get_object(test_fw.uid, analysis_filter=['crypto_material'])
        assert processed_fw.analysis_tags, 'tags not propagated properly'
        assert processed_fw.analysis_tags['crypto_material']['private_key_inside']
