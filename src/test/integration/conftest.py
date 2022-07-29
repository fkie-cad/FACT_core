import pytest
from scheduler.unpacking_scheduler import UnpackingScheduler
from tempfile import TemporaryDirectory
from multiprocessing import Queue
from pathlib import Path


class MockFSOrganizer:
    def __init__(self, *_, **__):
        self._data_folder = TemporaryDirectory()

    def store_file(self, file_object):
        Path(self._data_folder.name, file_object.uid).write_bytes(file_object.binary)

    def delete_file(self, uid):
        file_path = Path(self._data_folder.name, uid)
        if file_path.is_file():
            file_path.unlink()

    def generate_path(self, uid):
        return str(Path(self._data_folder.name, uid))

    def __del__(self):
        self._data_folder.cleanup()


# TODO rename
@pytest.fixture
def unpacking_queue():
    """TODO
    See also analysis_queue.
    """
    q = Queue()
    yield q
    q.close()


@pytest.fixture
def unpacking_scheduler(cfg_tuple, unpacking_lock_manager, analysis_scheduler, unpacking_queue) -> UnpackingScheduler:
    def post_unpack_cb(fw):
        unpacking_queue.put(fw)
        return analysis_scheduler.start_analysis_of_object()

    _, configparser_cfg = cfg_tuple
    sched = UnpackingScheduler(
        config=configparser_cfg,
        fs_organizer=MockFSOrganizer(),
        post_unpack=post_unpack_cb,
        unpacking_locks=unpacking_lock_manager,
    )

    yield sched

    sched.shutdown()
