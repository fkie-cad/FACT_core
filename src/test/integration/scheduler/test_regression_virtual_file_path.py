from multiprocessing import Event, Manager, Value
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
DUPLICATE_UID = '4d654c2089a27efb324c8038e2e10328cf9b3254b5f1263e29aa61fbc9bf6b52_168'
DUPLICATE_PARENT_1 = 'b835528aff2fc909517d877d6b9c2e67e7dab9372c738adcfb374006947cbeb2_976'
DUPLICATE_PARENT_2 = '03acd27c78d7ce2766b4c240f4f6eae4676870e805f378c0910edf70c27e1c2a_336'
INCLUDED_FILE_COUNT = 4


@pytest.fixture()
def finished_event():
    return Event()


@pytest.fixture()
def intermediate_event():
    return Event()


@pytest.fixture()
def unpacked_objects():
    manager = Manager()
    yield manager.list()
    manager.shutdown()


@pytest.fixture()
def test_scheduler(finished_event, intermediate_event, unpacked_objects):
    interface = BackendDbInterface()
    unpacking_lock_manager = UnpackingLockManager()
    elements_finished = Value('i', 0)

    def count_pre_analysis(file_object):
        interface.add_object(file_object)
        unpacked_objects.append(file_object.uid)
        elements_finished.value += 1
        if elements_finished.value == INCLUDED_FILE_COUNT:
            intermediate_event.set()
        elif elements_finished.value == INCLUDED_FILE_COUNT * 2:
            finished_event.set()

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
    assert len(fo_from_db.virtual_file_path) == 2, 'fo should have two parents'  # noqa: PLR2004
    assert FIRST_ROOT_ID in fo_from_db.virtual_file_path
    assert fo_from_db.virtual_file_path[FIRST_ROOT_ID] == ['/test']
    assert SECOND_ROOT_ID in fo_from_db.virtual_file_path
    assert fo_from_db.virtual_file_path[SECOND_ROOT_ID] == ['/test']


def test_unpacking_skip(db, test_scheduler, intermediate_event, unpacked_objects):
    add_test_file(test_scheduler, 'vfp_test.zip')

    assert intermediate_event.wait(timeout=20)

    assert len(list(unpacked_objects)) == INCLUDED_FILE_COUNT
    assert list(unpacked_objects).count(DUPLICATE_UID) == 1, 'is contained two times, 2nd unpacking should be skipped'
    fo_from_db = db.frontend.get_object(DUPLICATE_UID)
    assert fo_from_db.virtual_file_path == {
        DUPLICATE_PARENT_1: ['/folder/inner.zip'],
        DUPLICATE_PARENT_2: ['/inner.zip'],
    }, 'all VFPs should be there even if unpacking was skipped'
