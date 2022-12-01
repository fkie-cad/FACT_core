# pylint: disable=attribute-defined-outside-init,wrong-import-order,unused-argument
from objects.firmware import Firmware
from test.common_helper import get_test_data_dir
from test.integration.conftest import SchedulerTestConfig
import pytest


@pytest.mark.SchedulerTestConfig(
     SchedulerTestConfig(
         start_processes=True,
         pipeline=True,
     ),
)
def test_unpack_and_analyse(analysis_scheduler, unpacking_scheduler, post_analysis_queue):
    test_fw = Firmware(file_path=f'{get_test_data_dir()}/container/test.zip')

    unpacking_scheduler.add_task(test_fw)

    processed_container = {}
    for _ in range(4 * 2):  # container with 3 included files times 2 mandatory plugins run
        uid, plugin, analysis_result = post_analysis_queue.get(timeout=3)
        processed_container.setdefault(uid, {}).setdefault(plugin, {})
        processed_container[uid][plugin] = analysis_result

    assert len(processed_container) == 4, '4 files should have been analyzed'
    assert all(
        sorted(processed_analysis) == ['file_hashes', 'file_type']
        for processed_analysis in processed_container.values()
    ), 'at least one analysis not done'
