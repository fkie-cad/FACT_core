import pytest

from objects.firmware import Firmware
from test.common_helper import get_test_data_dir

uid_of_key_file = '530bf2f1203b789bfe054d3118ebd29a04013c587efd22235b3b9677cee21c0e_2048'


class TestTagPropagation:
    @pytest.mark.SchedulerTestConfig(
        # 5 objects * 3 analyses = 15 calls
        items_to_analyze=15,
        pipeline=True,
    )
    def test_run_analysis_with_tag(self, analysis_finished_event, unpacking_scheduler, backend_db, analysis_scheduler):
        test_fw = Firmware(file_path=f'{get_test_data_dir()}/container/with_key.7z')
        test_fw.version, test_fw.vendor, test_fw.device_name, test_fw.device_class = ['foo'] * 4
        test_fw.release_date = '2017-01-01'
        test_fw.scheduled_analysis = ['crypto_material']

        unpacking_scheduler.add_task(test_fw)

        assert analysis_finished_event.wait(timeout=20)

        processed_fo = backend_db.get_object(uid_of_key_file, analysis_filter=['crypto_material'])
        assert processed_fo.processed_analysis['crypto_material']['tags'], 'no tags set in analysis'

        processed_fw = backend_db.get_object(test_fw.uid, analysis_filter=['crypto_material'])
        assert processed_fw.analysis_tags, 'tags not propagated properly'
        assert processed_fw.analysis_tags['crypto_material']['private_key_inside']
