from multiprocessing import Event

import pytest

from objects.firmware import Firmware
from test.common_helper import get_test_data_dir


@pytest.mark.backend_config_overwrite(
    {
        'block_delay': 1,
        'unpacking': {
            'processes': 2,
            'max_depth': 3,
            'whitelist': [],
            'throttle_limit': 10,
        },
    },
)
@pytest.mark.SchedulerTestConfig(start_processes=True)
class TestUnpackScheduler:
    def test_unpack_a_container_including_another_container(self, unpacking_scheduler, post_unpack_queue):
        test_fw = Firmware(file_path=f'{get_test_data_dir()}/container/test_zip.tar.gz')
        included_files = [
            'ab4153d747f530f9bc3a4b71907386f50472ea5ae975c61c0bacd918f1388d4b_227',
            'faa11db49f32a90b51dfc3f0254f9fd7a7b46d0b570abd47e1943b86d554447a_28',
        ]
        unpacking_scheduler.add_task(test_fw)
        extracted_files = {}
        for _ in range(3):
            file = post_unpack_queue.get(timeout=5)
            extracted_files[file.uid] = file

        assert test_fw.uid in extracted_files
        assert len(extracted_files[test_fw.uid].files_included) == 2, 'not all children of fw found'
        assert (
            included_files[0] in extracted_files[test_fw.uid].files_included
        ), 'included container not extracted. Unpacker tar.gz module broken?'
        assert all(f in extracted_files for f in included_files)
        assert len(extracted_files[included_files[0]].files_included) == 1

    @pytest.mark.skip(reason='TODO this test is useless')
    def test_get_combined_analysis_workload(self, unpacking_scheduler):
        result = unpacking_scheduler._get_combined_analysis_workload()  # pylint: disable=protected-access
        assert result == 3, 'workload calculation not correct'

    @pytest.mark.backend_config_overwrite(
        {
            'unpacking': {
                'throttle_limit': -1,
            }
        }
    )
    @pytest.mark.SchedulerTestConfig(start_processes=False)
    def test_throttle(self, unpacking_scheduler, monkeypatch):
        sleep_was_called = Event()
        with monkeypatch.context() as mkp:
            mkp.setattr('scheduler.unpacking_scheduler.sleep', lambda _: sleep_was_called.set())
            unpacking_scheduler.start()
            unpacking_scheduler.work_load_process = unpacking_scheduler.start_work_load_monitor()

        assert sleep_was_called.wait(timeout=10)

        assert unpacking_scheduler.throttle_condition.value == 1, 'unpack load throttle not functional'

        unpacking_scheduler.shutdown()
