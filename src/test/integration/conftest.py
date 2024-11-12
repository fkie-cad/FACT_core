import pytest


# Integration tests test the system as a whole so one can reasonably expect the database to be populated.
@pytest.fixture(autouse=True)
def _autouse_database_interfaces(database_interfaces):
    pass
