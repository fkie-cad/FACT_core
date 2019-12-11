from multiprocessing import TimeoutError as MultiprocessingTimeoutError
from time import sleep

import pytest

from helperFunctions.process import ExceptionSafeProcess, timeout


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


@timeout(0.1)
def timeout_function(secs: float):
    sleep(secs)
    return True


def test_timeout():
    with pytest.raises(MultiprocessingTimeoutError):
        timeout_function(1)
    assert timeout_function(0.01)
