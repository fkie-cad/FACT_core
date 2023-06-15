# pylint: disable=attribute-defined-outside-init,too-many-instance-attributes
import gc
from multiprocessing import Event, Value
from tempfile import TemporaryDirectory

from helperFunctions.data_conversion import normalize_compare_id
from objects.firmware import Firmware
from scheduler.analysis import AnalysisScheduler
from scheduler.comparison_scheduler import ComparisonScheduler
from scheduler.unpacking_scheduler import UnpackingScheduler
from storage.db_interface_backend import BackendDbInterface
from storage.unpacking_locks import UnpackingLockManager
from test.common_helper import get_test_data_dir  # pylint: disable=wrong-import-order


class TestFileAddition:
    def setup(self):
        self._tmp_dir = TemporaryDirectory()
        self.elements_finished_analyzing = Value('i', 0)
        self.analysis_finished_event = Event()
        self.compare_finished_event = Event()

        self.backend_interface = BackendDbInterface()
        unpacking_lock_manager = UnpackingLockManager()

        self._analysis_scheduler = AnalysisScheduler(
            post_analysis=self.count_analysis_finished_event,
            unpacking_locks=unpacking_lock_manager,
        )
        self._analysis_scheduler.start()
        self._unpack_scheduler = UnpackingScheduler(
            post_unpack=self._analysis_scheduler.start_analysis_of_object,
            unpacking_locks=unpacking_lock_manager,
        )
        self._unpack_scheduler.start()
        self._comparison_scheduler = ComparisonScheduler(
            callback=self.trigger_compare_finished_event,
        )
        self._comparison_scheduler.start()

    def count_analysis_finished_event(self, uid, plugin, analysis_result):
        self.backend_interface.add_analysis(uid, plugin, analysis_result)
        self.elements_finished_analyzing.value += 1
        if self.elements_finished_analyzing.value == 4 * 2 * 2:  # 2 container with 3 files each and 2 plugins
            self.analysis_finished_event.set()

    def trigger_compare_finished_event(self):
        self.compare_finished_event.set()

    def teardown(self):
        self._comparison_scheduler.shutdown()
        self._unpack_scheduler.shutdown()
        self._analysis_scheduler.shutdown()
        self._tmp_dir.cleanup()
        gc.collect()

    def test_unpack_analyse_and_compare(self, db, comp_db):
        test_fw_1 = Firmware(file_path=f'{get_test_data_dir()}/container/test.zip')
        test_fw_2 = Firmware(file_path=f'{get_test_data_dir()}/regression_one')

        for fw in [test_fw_1, test_fw_2]:
            fw.version, fw.vendor, fw.device_name, fw.device_class = ['foo'] * 4
            fw.release_date = '2017-01-01'
            self._unpack_scheduler.unpacker.file_storage_system.store_file(fw)
            self._unpack_scheduler.add_task(fw)

        assert self.analysis_finished_event.wait(timeout=20)

        compare_id = normalize_compare_id(';'.join([fw.uid for fw in [test_fw_1, test_fw_2]]))

        assert self._comparison_scheduler.add_task((compare_id, False)) is None, 'adding comparison task creates error'

        assert self.compare_finished_event.wait(timeout=10)

        result = comp_db.get_comparison_result(compare_id)

        assert result is not None, 'comparison result not found in DB'
        assert result['plugins']['Software'] == self._expected_result()['Software']
        assert len(result['plugins']['File_Coverage']['files_in_common']) == len(
            self._expected_result()['File_Coverage']['files_in_common']
        )

    @staticmethod
    def _expected_result():
        return {
            'File_Coverage': {'files_in_common': {'all': [], 'collapse': False}},
            'Software': {'Compare Skipped': {'all': 'Required analysis not present: software_components'}},
        }
