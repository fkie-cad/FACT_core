from __future__ import annotations

from contextlib import contextmanager
from typing import ContextManager, TypeVar

DatabaseInterface = TypeVar('DatabaseInterface')


@contextmanager
def get_shared_session(database: DatabaseInterface) -> ContextManager[DatabaseInterface]:
    with database.get_read_only_session():
        yield database
