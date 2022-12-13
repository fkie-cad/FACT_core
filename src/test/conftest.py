import dataclasses
from typing import Type, TypeVar

import pytest

from storage.db_setup import DbSetup
from test.common_helper import clear_test_tables, setup_test_tables


T = TypeVar('T')


def merge_markers(request, name: str, dtype: Type[T]) -> T:
    """Merge all markers from closest to farthest. Closer markers overwrite markers that are farther away.

    Optionally a dict with keys matching the ones in ``dtype`` can be used.
    The constructor of ``dtype`` must accept all possible values as kwargs.

    :param request: The pytest request where the markers will be taken from.
    :param name: The name of the marker.
    :param dtype: The type that the marker should have. Must be a ``pydantic.dataclasses.dataclass``.

    :return: An instance of ``dtype``.
    """
    # Not well documented but iter_markers iterates from closest to farthest
    # https://docs.pytest.org/en/7.1.x/reference/reference.html?highlight=iter_markers#custom-marks
    marker_dict = {}
    for marker in reversed(list(request.node.iter_markers(name))):
        dict_or_dtype = marker.args[0]
        if isinstance(dict_or_dtype, dict):
            marker_dict.update(dict_or_dtype)
        elif isinstance(dict_or_dtype, dtype):
            marker_dict.update(dataclasses.asdict(dict_or_dtype))
        else:
            raise ValueError(f'The argument to marker {name} must be either a dict or an instance of {dtype}.')

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
