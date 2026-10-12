import logging
import subprocess
from multiprocessing import Event
from time import sleep

import psutil
import pytest

from helperFunctions.process import (
    ExceptionSafeProcess,
    _stop_psutil_process,
    check_worker_exceptions,
    new_worker_was_started,
)

check_exceptions_finished = Event()


def breaking_process(wait: bool = False):
    if wait:
        check_exceptions_finished.wait(timeout=5)
    raise RuntimeError("now that's annoying")


def test_exception_safe_process():
    with pytest.raises(RuntimeError):
        breaking_process()

    process = ExceptionSafeProcess(target=breaking_process)
    process.start()
    process.join()
    assert process.exception
    assert str(process.exception[0]) == "now that's annoying"


@pytest.mark.flaky(reruns=3)  # test may fail on stressed systems
@pytest.mark.backend_config_overwrite(
    {
        'throw_exceptions': True,
    }
)
def test_check_worker_exceptions():
    check_exceptions_finished.clear()
    process_list = [ExceptionSafeProcess(target=breaking_process, args=(True,))]
    process_list[0].start()

    result = check_worker_exceptions(process_list, 'foo')
    check_exceptions_finished.set()
    assert not result
    assert len(process_list) == 1

    sleep(0.1)  # give worker some time to raise the exception
    result = check_worker_exceptions(process_list, 'foo')
    assert result
    assert len(process_list) == 0


@pytest.mark.flaky(reruns=3)  # test may fail on stressed systems
@pytest.mark.backend_config_overwrite(
    {
        'throw_exceptions': False,
    }
)
def test_check_worker_restart(caplog):
    check_exceptions_finished.clear()
    worker = ExceptionSafeProcess(target=breaking_process, args=(True,))
    process_list = [worker]
    worker.start()

    check_exceptions_finished.set()
    sleep(0.1)
    try:
        with caplog.at_level(logging.INFO):
            result = check_worker_exceptions(process_list, 'foo', worker_function=lambda _: None)
            assert not result
            assert len(process_list) == 1
            assert process_list[0] != worker
            assert 'Exception in foo' in caplog.messages[0]
            assert 'restarting foo' in caplog.messages[-1]
    finally:
        worker.join()


def test_new_worker_was_started():
    def target():
        pass

    old, new = ExceptionSafeProcess(target=target), ExceptionSafeProcess(target=target)

    assert new_worker_was_started(old, new)
    assert not new_worker_was_started(old, old)


@pytest.mark.parametrize('wait_first', [True, False])
def test_stop_psutil_process_kills_hanging_process(wait_first):
    # the process ignores SIGTERM, so it must be killed after the timeout
    proc = subprocess.Popen(['/bin/sh', '-c', 'trap "" TERM; sleep 30'])
    try:
        sleep(0.1)  # make sure the trap is set before sending SIGTERM
        _stop_psutil_process(psutil.Process(proc.pid), timeout=0.2, wait_first=wait_first)
        assert proc.poll() is not None
    finally:
        proc.kill()
        proc.wait()


def test_stop_psutil_process_already_stopped():
    proc = subprocess.Popen(['/bin/sh', '-c', 'exit 0'])
    ps_proc = psutil.Process(proc.pid)
    proc.wait()
    _stop_psutil_process(ps_proc, timeout=0.2, wait_first=True)  # should not raise
