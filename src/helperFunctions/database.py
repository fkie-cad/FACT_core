from __future__ import annotations

from contextlib import contextmanager
from typing import TypeVar, Iterator

from storage.db_interface_base import ReadOnlyDbInterface

DatabaseInterface = TypeVar('DatabaseInterface', bound=ReadOnlyDbInterface)


@contextmanager
def get_shared_session(database: DatabaseInterface) -> Iterator[DatabaseInterface]:
    with database.get_read_only_session():
        yield database
