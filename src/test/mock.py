from contextlib import contextmanager
from typing import Callable


class MockSpy:
    _called = False
    _args = None

    def spy_function(self, *args):
        self._called = True
        self._args = args

    def was_called(self):
        return self._called


@contextmanager
def mock_spy(o: object, method: str):
    spy = MockSpy()
    if not hasattr(o, method):
        raise AttributeError(f'{type(o)} has no method {method}')
    tmp = getattr(o, method)
    try:
        setattr(o, method, spy.spy_function)
        yield spy
    finally:
        setattr(o, method, tmp)


@contextmanager
def mock_patch(o: object, method: str, replacement_method: Callable):
    if not hasattr(o, method):
        raise AttributeError(f'{type(o)} has no method {method}')
    tmp = getattr(o, method)
    try:
        setattr(o, method, replacement_method)
        yield o
    finally:
        setattr(o, method, tmp)
