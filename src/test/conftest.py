import dataclasses
from typing import Type, TypeVar

import pytest

from storage.db_setup import DbSetup
from test.common_helper import clear_test_tables, setup_test_tables

T = TypeVar('T')


def merge_markers(request, name: str, dtype: Type[T]) -> T:
    """Merge all markers from closest to farthest. Closer markers overwrite markers that are farther away.

    The marker must either get an instance of ``dtype`` as an argument or have one or more keyword arguments.
    The keyword arguments must be accepted by the ``dtype.__init__``.``

    :param request: The pytest request where the markers will be taken from.
    :param name: The name of the marker.
    :param dtype: The type that the marker should have. Must be a ``pydantic.dataclasses.dataclass`` or ``dict``.

    :return: An instance of ``dtype``.
    """
    _err = ValueError(
        f'The argument(s) to marker {name} must be either an instance of {dtype} or keyword arguments, not both.'
    )
    # Not well documented but iter_markers iterates from closest to farthest
    # https://docs.pytest.org/en/7.1.x/reference/reference.html?highlight=iter_markers#custom-marks
    marker_dict = {}
    for marker in reversed(list(request.node.iter_markers(name))):
        if marker.kwargs and marker.args:
            raise _err

        if marker.kwargs:
            marker_dict.update(marker.kwargs)
        elif marker.args:
            argument = marker.args[0]
            assert isinstance(argument, dtype)
            if isinstance(argument, dict):
                marker_dict.update(argument)
            else:
                marker_dict.update(dataclasses.asdict(argument))
        else:
            raise _err
    return dtype(**marker_dict)


@pytest.fixture
def create_tables():
    """Creates the tables that backend needs.
    This is equivalent to executing ``init_postgres.py``.
    """
    db_setup = DbSetup()
    setup_test_tables(db_setup)
    yield
    clear_test_tables(db_setup)
