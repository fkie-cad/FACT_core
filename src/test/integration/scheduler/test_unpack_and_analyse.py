import pytest

from objects.firmware import Firmware
from test.common_helper import get_test_data_dir


# TODO the test passes without this
@pytest.mark.usefixtures('use_database')
def test_unpack_and_analyse(analysis_scheduler, analysis_queue, unpacking_scheduler):
    test_fw = Firmware(file_path=f'{get_test_data_dir()}/container/test.zip')

    unpacking_scheduler.add_task(test_fw)

    processed_container = {}
    for _ in range(4 * 2):  # container with 3 included files times 2 mandatory plugins run
        x = analysis_queue.get(timeout=10)
        uid, plugin, analysis_result = x['uid'], x['plugin'], x['result']

        processed_container.setdefault(uid, {}).setdefault(plugin, {})
        processed_container[uid][plugin] = analysis_result

    assert len(processed_container) == 4, '4 files should have been analyzed'
    assert all(
        sorted(processed_analysis) == ['file_hashes', 'file_type']
        for processed_analysis in processed_container.values()
    ), 'at least one analysis not done'
