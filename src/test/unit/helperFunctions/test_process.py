import logging
from multiprocessing import TimeoutError as MultiprocessingTimeoutError
from time import sleep

import pytest

from helperFunctions.process import ExceptionSafeProcess, check_worker_exceptions, new_worker_was_started, timeout
from test.common_helper import get_config_for_testing


def breaking_process(wait: bool = False):
    if wait:
        sleep(.5)
    raise RuntimeError('now that\'s annoying')


def test_exception_safe_process():
    with pytest.raises(RuntimeError):
        breaking_process()

    process = ExceptionSafeProcess(target=breaking_process)
    process.start()
    process.join()
    assert process.exception
    assert str(process.exception[0]) == 'now that\'s annoying'


def test_check_worker_exceptions():
    config = get_config_for_testing()
    config.set('ExpertSettings', 'throw_exceptions', 'true')

    process_list = [ExceptionSafeProcess(target=breaking_process, args=(True, ))]
    process_list[0].start()

    result = check_worker_exceptions(process_list, 'foo', config=config)
    assert not result
    assert len(process_list) == 1
    sleep(1)
    result = check_worker_exceptions(process_list, 'foo', config=config)
    assert result
    assert len(process_list) == 0


def test_check_worker_restart(caplog):
    config = get_config_for_testing()
    config.set('ExpertSettings', 'throw_exceptions', 'false')

    worker = ExceptionSafeProcess(target=breaking_process, args=(True, ))
    process_list = [worker]
    worker.start()

    sleep(1)
    with caplog.at_level(logging.INFO):
        result = check_worker_exceptions(process_list, 'foo', config, worker_function=lambda _: None)
        assert not result
        assert len(process_list) == 1
        assert process_list[0] != worker
        assert 'Exception in foo' in caplog.messages[0]
        assert 'restarting foo' in caplog.messages[-1]
        process_list[0].join()


def test_timeout():
    @timeout(0.1)
    def timeout_function(secs: float):
        sleep(secs)
        return True

    with pytest.raises(MultiprocessingTimeoutError):
        timeout_function(1)
    assert timeout_function(0.01)


def test_new_worker_was_started():
    def target():
        pass

    old, new = ExceptionSafeProcess(target=target), ExceptionSafeProcess(target=target)

    assert new_worker_was_started(old, new)
    assert not new_worker_was_started(old, old)
