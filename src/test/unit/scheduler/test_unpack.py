import logging
from multiprocessing import Event, Lock, Manager

import pytest

from objects.file import FileObject
from objects.firmware import Firmware
from test.common_helper import get_test_data_dir

TEST_FW = Firmware(file_path=f'{get_test_data_dir()}/container/test_zip.7z')


class MockDb:
    def __init__(self):
        self.manager = Manager()
        self.counter = self.manager.Value('i', 0)

    def add_object(self, fw_object):
        self.counter.value += 1

    def __call__(self, *args, **kwargs):  # hack: object can be instantiated again
        return self


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
        included_files = [
            'ab4153d747f530f9bc3a4b71907386f50472ea5ae975c61c0bacd918f1388d4b_227',
            'faa11db49f32a90b51dfc3f0254f9fd7a7b46d0b570abd47e1943b86d554447a_28',
        ]
        unpacking_scheduler.add_task(TEST_FW)
        extracted_files = {}
        for _ in range(4):
            file = post_unpack_queue.get(timeout=5)
            extracted_files[file.uid] = file

        assert TEST_FW.uid in extracted_files
        assert len(extracted_files[TEST_FW.uid].files_included) == 2, 'not all children of fw found'
        assert (
            included_files[0] in extracted_files[TEST_FW.uid].files_included
        ), 'included container not extracted. Unpacker tar.gz module broken?'
        assert all(f in extracted_files for f in included_files)
        assert len(extracted_files[included_files[0]].files_included) == 1

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


def test_cancel_unpacking(unpacking_scheduler, caplog):
    unpacking_scheduler.sync_lock = Lock()
    unpacking_scheduler.currently_extracted = {}
    test_fo = FileObject(binary=b'foo')
    test_fo.uid = 'foo'
    test_fo.root_uid = TEST_FW.uid

    # this should not cause an error even if the FW is not currently being unpacked
    unpacking_scheduler.cancel_unpacking(TEST_FW.uid)

    unpacking_scheduler._init_currently_unpacked(TEST_FW)
    assert TEST_FW.uid in unpacking_scheduler.currently_extracted

    unpacking_scheduler.cancel_unpacking(TEST_FW.uid)
    assert TEST_FW.uid not in unpacking_scheduler.currently_extracted

    with caplog.at_level(logging.DEBUG):
        unpacking_scheduler.work_thread(test_fo, None)
    assert any('Cancelling unpacking' in m for m in caplog.messages)
