import logging
from time import sleep

import pytest

from helperFunctions.process import ExceptionSafeProcess, check_worker_exceptions
from test.common_helper import get_config_for_testing


def breaking_process():
    raise RuntimeError('now that\'s annoying')


def test_exception_safe_process():
    with pytest.raises(RuntimeError):
        breaking_process()

    process = ExceptionSafeProcess(target=breaking_process)
    process.start()
    process.join()
    assert process.exception
    assert str(process.exception[0]) == 'now that\'s annoying'


def _worker_with_exception():
    sleep(.25)
    raise Exception('foobar')


def test_check_worker_exceptions():
    config = get_config_for_testing()
    config.set('ExpertSettings', 'throw_exceptions', 'true')

    process_list = [ExceptionSafeProcess(target=_worker_with_exception)]
    process_list[0].start()

    result = check_worker_exceptions(process_list, 'foo', config=config)
    assert not result
    assert len(process_list) == 1
    sleep(.5)
    result = check_worker_exceptions(process_list, 'foo', config=config)
    assert result
    assert len(process_list) == 0


def test_check_worker_restart(caplog):
    config = get_config_for_testing()
    config.set('ExpertSettings', 'throw_exceptions', 'false')

    worker = ExceptionSafeProcess(target=_worker_with_exception)
    process_list = [worker]
    worker.start()

    sleep(.5)
    with caplog.at_level(logging.INFO):
        result = check_worker_exceptions(process_list, 'foo', config, worker_function=lambda: None)
        assert not result
        assert len(process_list) == 1
        assert process_list[0] != worker
        assert 'Exception in foo' in caplog.messages[0]
        assert 'restarting foo' in caplog.messages[-1]
        process_list[0].join()
