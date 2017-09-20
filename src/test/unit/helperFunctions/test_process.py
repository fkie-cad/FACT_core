from helperFunctions.process import ExceptionSafeProcess
import pytest


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
