from __future__ import annotations

from queue import Empty
from typing import TYPE_CHECKING

import pytest

from objects.firmware import Firmware
from test.common_helper import get_test_data_dir

if TYPE_CHECKING:
    from multiprocessing import Queue

FIRST_ROOT_ID = '5fadb36c49961981f8d87cc21fc6df73a1b90aa1857621f2405d317afb994b64_68415'
SECOND_ROOT_ID = '0383cac1dd8fbeb770559163edbd571c21696c435a4942bec6df151983719731_52143'
TARGET_UID = '49543bc7128542b062d15419c90459be65ca93c3134554bc6224e307b359c021_9968'
DUPLICATE_UID = '4d654c2089a27efb324c8038e2e10328cf9b3254b5f1263e29aa61fbc9bf6b52_168'
DUPLICATE_PARENT_1 = 'b835528aff2fc909517d877d6b9c2e67e7dab9372c738adcfb374006947cbeb2_976'
DUPLICATE_PARENT_2 = '03acd27c78d7ce2766b4c240f4f6eae4676870e805f378c0910edf70c27e1c2a_336'
INCLUDED_FILE_COUNT = 4


def add_test_file(scheduler, path_in_test_dir):
    firmware = Firmware(file_path=str(get_test_data_dir() / path_in_test_dir))
    firmware.release_date = '1990-01-16'
    firmware.version, firmware.vendor, firmware.device_name, firmware.device_class = ['foo'] * 4
    scheduler.add_task(firmware)


@pytest.mark.flaky(reruns=3)  # test may fail when the CI is very busy
@pytest.mark.SchedulerTestConfig(items_to_unpack=4)
def test_check_collision(
    frontend_db,
    unpacking_scheduler,
    unpacking_finished_counter,
    unpacking_finished_event,
):
    add_test_file(unpacking_scheduler, 'regression_one')
    assert unpacking_finished_event.wait(timeout=25)
    unpacking_finished_counter.value = 0
    unpacking_finished_event.clear()

    add_test_file(unpacking_scheduler, 'regression_two')
    assert unpacking_finished_event.wait(timeout=25)

    fo_from_db = frontend_db.get_object(TARGET_UID)
    assert len(fo_from_db.virtual_file_path) == 2, 'fo should have two parents'
    assert FIRST_ROOT_ID in fo_from_db.virtual_file_path
    assert fo_from_db.virtual_file_path[FIRST_ROOT_ID] == ['/test']
    assert SECOND_ROOT_ID in fo_from_db.virtual_file_path
    assert fo_from_db.virtual_file_path[SECOND_ROOT_ID] == ['/test']


@pytest.mark.flaky(reruns=3)  # test may fail when the CI is very busy
@pytest.mark.SchedulerTestConfig(items_to_unpack=4)
def test_unpacking_skip(
    frontend_db,
    unpacking_scheduler,
    unpacking_finished_event,
    post_unpack_queue,
):
    add_test_file(unpacking_scheduler, 'vfp_test.zip')

    assert unpacking_finished_event.wait(timeout=25)

    unpacked_objects = _collect_unpacked_files(post_unpack_queue)
    assert len(list(unpacked_objects)) == INCLUDED_FILE_COUNT
    assert unpacked_objects.count(DUPLICATE_UID) == 1, 'is contained two times, 2nd unpacking should be skipped'
    fo_from_db = frontend_db.get_object(DUPLICATE_UID)
    assert fo_from_db.virtual_file_path == {
        DUPLICATE_PARENT_1: ['/folder/inner.zip'],
        DUPLICATE_PARENT_2: ['/inner.zip'],
    }, 'all VFPs should be there even if unpacking was skipped'


def _collect_unpacked_files(queue: Queue) -> list[str]:
    result = []
    while True:
        try:
            fo = queue.get(timeout=0)
            result.append(fo.uid)
        except Empty:
            return result
