import logging
from time import sleep

import pytest

from fact.helperFunctions.process import ExceptionSafeProcess, check_worker_exceptions, new_worker_was_started


def breaking_process(wait: bool = False):
    if wait:
        sleep(0.5)
    raise RuntimeError("now that's annoying")


def test_exception_safe_process():
    with pytest.raises(RuntimeError):
        breaking_process()

    process = ExceptionSafeProcess(target=breaking_process)
    process.start()
    process.join()
    assert process.exception
    assert str(process.exception[0]) == "now that's annoying"


@pytest.mark.backend_config_overwrite(
    {
        'throw_exceptions': True,
    }
)
def test_check_worker_exceptions():
    process_list = [ExceptionSafeProcess(target=breaking_process, args=(True,))]
    process_list[0].start()

    result = check_worker_exceptions(process_list, 'foo')
    assert not result
    assert len(process_list) == 1
    sleep(1)
    result = check_worker_exceptions(process_list, 'foo')
    assert result
    assert len(process_list) == 0


@pytest.mark.backend_config_overwrite(
    {
        'throw_exceptions': False,
    }
)
def test_check_worker_restart(caplog):
    worker = ExceptionSafeProcess(target=breaking_process, args=(True,))
    process_list = [worker]
    worker.start()

    sleep(1)
    with caplog.at_level(logging.INFO):
        result = check_worker_exceptions(process_list, 'foo', worker_function=lambda _: None)
        assert not result
        assert len(process_list) == 1
        assert process_list[0] != worker
        assert 'Exception in foo' in caplog.messages[0]
        assert 'restarting foo' in caplog.messages[-1]
        process_list[0].join()


def test_new_worker_was_started():
    def target():
        pass

    old, new = ExceptionSafeProcess(target=target), ExceptionSafeProcess(target=target)

    assert new_worker_was_started(old, new)
    assert not new_worker_was_started(old, old)
