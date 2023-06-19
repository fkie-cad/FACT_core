from multiprocessing import Event, Value
from pathlib import Path

import pytest

from objects.firmware import Firmware
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


@pytest.fixture
def test_scheduler(finished_event, intermediate_event):
    interface = BackendDbInterface()
    unpacking_lock_manager = UnpackingLockManager()
    elements_finished = Value('i', 0)

    def count_pre_analysis(file_object):
        interface.add_object(file_object)
        elements_finished.value += 1
        if elements_finished.value == 8:
            finished_event.set()
        elif elements_finished.value == 4:
            intermediate_event.set()

    unpacker = UnpackingScheduler(
        post_unpack=count_pre_analysis,
        unpacking_locks=unpacking_lock_manager,
    )
    unpacker.start()
    try:
        yield unpacker
    finally:
        unpacker.shutdown()
        unpacking_lock_manager.shutdown()


def add_test_file(scheduler: UnpackingScheduler, path_in_test_dir: str):
    firmware = Firmware(file_path=str(Path(get_test_data_dir(), path_in_test_dir)))
    firmware.release_date = '1990-01-16'
    firmware.version, firmware.vendor, firmware.device_name, firmware.device_class = ['foo'] * 4
    scheduler.add_task(firmware)


def test_check_collision(db, test_scheduler, finished_event, intermediate_event):
    add_test_file(test_scheduler, 'regression_one')

    assert intermediate_event.wait(timeout=5)

    add_test_file(test_scheduler, 'regression_two')

    assert finished_event.wait(timeout=30)

    fo_from_db = db.frontend.get_object(TARGET_UID)
    assert len(fo_from_db.virtual_file_path) == 2, 'fo should have two parents'
    assert FIRST_ROOT_ID in fo_from_db.virtual_file_path
    assert fo_from_db.virtual_file_path[FIRST_ROOT_ID] == ['/test']
    assert SECOND_ROOT_ID in fo_from_db.virtual_file_path
    assert fo_from_db.virtual_file_path[SECOND_ROOT_ID] == ['/test']
