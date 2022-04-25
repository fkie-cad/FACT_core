# pylint: disable=no-self-use
import gc
from multiprocessing import Queue

import pytest

from scheduler.analysis import AnalysisScheduler
from storage.unpacking_locks import UnpackingLockManager


class ViewUpdaterMock:
    def update_view(self, *_):
        pass


class BackendDbInterface:
    def get_analysis(self, *_):
        pass


@pytest.fixture
def analysis_queue():
    queue = Queue()

    yield queue

    queue.close()
    gc.collect()


@pytest.fixture
def analysis_scheduler(monkeypatch, analysis_queue, cfg_tuple) -> AnalysisScheduler:
    monkeypatch.setattr('plugins.base.ViewUpdater', lambda *_: ViewUpdaterMock())

    _, configparser_cfg = cfg_tuple

    mocked_interface = BackendDbInterface()

    # TODO rename
    def dummy_callback(uid, plugin, analysis_result):
        analysis_queue.put({'uid': uid, 'plugin': plugin, 'result': analysis_result})

    sched = AnalysisScheduler(
        config=configparser_cfg,
        pre_analysis=lambda *_: None,
        post_analysis=dummy_callback,
        db_interface=mocked_interface,
        unpacking_locks=UnpackingLockManager()
    )

    yield sched

    sched.shutdown()
