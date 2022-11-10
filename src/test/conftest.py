import pytest

from storage.db_setup import DbSetup
from test.common_helper import clear_test_tables, setup_test_tables


@pytest.fixture
def create_tables():
    """Creates the tables that backend needs.
    This is equivalent to executing ``init_postgres.py``.
    """
    db_setup = DbSetup()
    setup_test_tables(db_setup)
    yield
    clear_test_tables(db_setup)
