import pytest

from storage.db_setup import DbSetup
from test.common_helper import clear_test_tables, setup_test_tables


# TODO Consider changing this function to have a higher scope that function.
# Currently this is not possible because the cfg_tuple fixture must have function
# scope and this fixture needs it.
# TODO This function should only be used by integration tests -> Move it to to integration/conftest.py
@pytest.fixture
def create_tables():
    """Creates the tables that backend needs.
    This is equivalent to executing ``init_postgres.py``.
    """
    db_setup = DbSetup()
    setup_test_tables(db_setup)
    yield
    clear_test_tables(db_setup)
