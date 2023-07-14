import pytest

from helperFunctions.data_conversion import normalize_compare_id
from objects.firmware import Firmware
from storage.db_interface_backend import BackendDbInterface
from test.common_helper import get_test_data_dir

_expected_result = {
    'File_Coverage': {'files_in_common': {'all': [], 'collapse': False}},
    'Software': {'Compare Skipped': {'all': 'Required analysis not present: software_components'}},
}


class TestFileAddition:
    @pytest.mark.SchedulerTestConfig(
        # 2 container with 3 files each and 2 plugins
        items_to_analyze=4 * 2 * 2,
        start_processes=True,
        pipeline=True,
        backend_db_class=BackendDbInterface,
    )
    def test_unpack_analyse_and_compare(  # noqa: PLR0913
        self,
        backend_db,
        unpacking_scheduler,
        analysis_scheduler,
        comparison_scheduler,
        comparison_db,
        analysis_finished_event,
        comparison_finished_event,
        post_analysis_queue,
    ):
        test_fw_1 = Firmware(file_path=f'{get_test_data_dir()}/container/test.zip')
        test_fw_2 = Firmware(file_path=f'{get_test_data_dir()}/regression_one')

        for fw in [test_fw_1, test_fw_2]:
            fw.version, fw.vendor, fw.device_name, fw.device_class = ['foo'] * 4
            fw.release_date = '2017-01-01'
            unpacking_scheduler.unpacker.file_storage_system.store_file(fw)
            unpacking_scheduler.add_task(fw)

        assert analysis_finished_event.wait(timeout=20)

        compare_id = normalize_compare_id(';'.join([fw.uid for fw in [test_fw_1, test_fw_2]]))

        assert comparison_scheduler.add_task((compare_id, False)) is None, 'adding comparison task creates error'

        assert comparison_finished_event.wait(timeout=10)

        result = comparison_db.get_comparison_result(compare_id)

        assert result is not None, 'comparison result not found in DB'
        assert result['plugins']['Software'] == _expected_result['Software']
        assert len(result['plugins']['File_Coverage']['files_in_common']) == len(
            _expected_result['File_Coverage']['files_in_common']
        )
