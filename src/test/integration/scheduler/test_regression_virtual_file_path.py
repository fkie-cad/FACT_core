# pylint: disable=no-self-use
# pylint: disable=redefined-outer-name,wrong-import-order
from multiprocessing import Event, Value
from pathlib import Path

import pytest

from intercom.back_end_binding import InterComBackEndBinding
from objects.firmware import Firmware
from scheduler.analysis import AnalysisScheduler
from scheduler.unpacking_scheduler import UnpackingScheduler
from storage.db_interface_backend import BackendDbInterface
from storage.unpacking_locks import UnpackingLockManager
from test.common_helper import get_test_data_dir

FIRST_ROOT_ID = '5fadb36c49961981f8d87cc21fc6df73a1b90aa1857621f2405d317afb994b64_68415'
SECOND_ROOT_ID = '0383cac1dd8fbeb770559163edbd571c21696c435a4942bec6df151983719731_52143'
TARGET_UID = '49543bc7128542b062d15419c90459be65ca93c3134554bc6224e307b359c021_9968'


class MockScheduler:
    def __init__(self, *_, **__):
        pass

    def add_task(self, task):
        pass


@pytest.fixture
def finished_event():
    return Event()


@pytest.fixture
def intermediate_event():
    return Event()


# TODO scope=module
@pytest.fixture
def test_scheduler(cfg_tuple, finished_event, intermediate_event):
    """TODO
    nothing is mocked
    """
    _, configparser_cfg = cfg_tuple
    interface = BackendDbInterface(config=configparser_cfg)
    unpacking_lock_manager = UnpackingLockManager()
    elements_finished = Value('i', 0)

    def count_pre_analysis(file_object):
        interface.add_object(file_object)
        elements_finished.value += 1
        if elements_finished.value == 16:
            finished_event.set()
        elif elements_finished.value == 8:
            intermediate_event.set()

    analyzer = AnalysisScheduler(
        configparser_cfg, pre_analysis=count_pre_analysis, db_interface=interface, unpacking_locks=unpacking_lock_manager
    )
    unpacker = UnpackingScheduler(
        config=configparser_cfg, post_unpack=analyzer.start_analysis_of_object, unpacking_locks=unpacking_lock_manager
    )
    intercom = InterComBackEndBinding(
        config=configparser_cfg, analysis_service=analyzer, unpacking_service=unpacker, compare_service=MockScheduler(),
        unpacking_locks=unpacking_lock_manager
    )
    try:
        yield unpacker
    finally:
        intercom.shutdown()
        unpacker.shutdown()
        analyzer.shutdown()


def add_test_file(scheduler, path_in_test_dir):
    firmware = Firmware(file_path=str(Path(get_test_data_dir(), path_in_test_dir)))
    firmware.release_date = '1990-01-16'
    firmware.version, firmware.vendor, firmware.device_name, firmware.device_class = ['foo'] * 4
    scheduler.add_task(firmware)


@pytest.mark.usefixtures('use_database')
def test_check_collision(test_client, test_scheduler, finished_event, intermediate_event):  # pylint: disable=unused-argument
    add_test_file(test_scheduler, 'regression_one')

    intermediate_event.wait(timeout=30)

    add_test_file(test_scheduler, 'regression_two')

    finished_event.wait(timeout=30)

    first_response = test_client.get(f'/analysis/{TARGET_UID}/ro/{FIRST_ROOT_ID}')
    assert b'insufficient information' not in first_response.data

    second_response = test_client.get(f'/analysis/{TARGET_UID}/ro/{SECOND_ROOT_ID}')
    assert b'insufficient information' not in second_response.data
