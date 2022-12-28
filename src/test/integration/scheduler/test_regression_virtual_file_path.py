# pylint: disable=redefined-outer-name,wrong-import-order
from pathlib import Path

import pytest

from objects.firmware import Firmware
from test.common_helper import get_test_data_dir
from web_interface.frontend_main import WebFrontEnd

FIRST_ROOT_ID = '5fadb36c49961981f8d87cc21fc6df73a1b90aa1857621f2405d317afb994b64_68415'
SECOND_ROOT_ID = '0383cac1dd8fbeb770559163edbd571c21696c435a4942bec6df151983719731_52143'
TARGET_UID = '49543bc7128542b062d15419c90459be65ca93c3134554bc6224e307b359c021_9968'


def add_test_file(scheduler, path_in_test_dir):
    firmware = Firmware(file_path=str(Path(get_test_data_dir(), path_in_test_dir)))
    firmware.release_date = '1990-01-16'
    firmware.version, firmware.vendor, firmware.device_name, firmware.device_class = ['foo'] * 4
    scheduler.add_task(firmware)


@pytest.fixture
def test_client():
    _web_frontend = WebFrontEnd()
    _web_frontend.app.config['TESTING'] = True
    return _web_frontend.app.test_client()


# This is a bit hacky, we set items_to_analyze to zero and manually set the counter to a negative value
# This way we can easily finish multiple analyses
@pytest.mark.SchedulerTestConfig(items_to_analyze=0, pipeline=True)
def test_check_collision(
    test_client,
    analysis_scheduler,
    unpacking_scheduler,
    analysis_finished_event,
    analysis_finished_counter,
):  # pylint: disable=unused-argument
    analysis_finished_counter.value = -8

    add_test_file(unpacking_scheduler, 'regression_one')

    assert analysis_finished_event.wait(timeout=30)
    analysis_finished_event.clear()
    analysis_finished_counter.value = -6

    add_test_file(unpacking_scheduler, 'regression_two')

    assert analysis_finished_event.wait(timeout=30)

    first_response = test_client.get(f'/analysis/{TARGET_UID}/ro/{FIRST_ROOT_ID}')
    assert b'insufficient information' not in first_response.data

    second_response = test_client.get(f'/analysis/{TARGET_UID}/ro/{SECOND_ROOT_ID}')
    assert b'insufficient information' not in second_response.data
