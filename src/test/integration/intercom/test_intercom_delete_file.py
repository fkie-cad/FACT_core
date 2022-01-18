# pylint: disable=redefined-outer-name,wrong-import-order
import logging

import pytest

from intercom.back_end_binding import InterComBackEndDeleteFile
from test.common_helper import CommonDatabaseMock, get_config_for_testing
from test.integration.common import MockFSOrganizer


@pytest.fixture(scope='function', autouse=True)
def mocking_the_database(monkeypatch):
    monkeypatch.setattr('storage_postgresql.db_interface_common.DbInterfaceCommon.__init__', lambda *_, **__: None)
    monkeypatch.setattr('storage_postgresql.db_interface_common.DbInterfaceCommon.__new__', lambda *_, **__: CommonDatabaseMock())
    monkeypatch.setattr('intercom.common_mongo_binding.InterComListener.__init__', lambda self, config: None)


@pytest.fixture(scope='function')
def config():
    return get_config_for_testing()


@pytest.fixture(scope='function')
def mock_listener(config):
    listener = InterComBackEndDeleteFile(config)
    listener.fs_organizer = MockFSOrganizer(None)
    listener.config = config
    return listener


def test_delete_file_success(mock_listener, caplog):
    with caplog.at_level(logging.INFO):
        mock_listener.post_processing('AnyID', None)
        assert 'remove file: AnyID' in caplog.messages


def test_delete_file_entry_exists(mock_listener, monkeypatch, caplog):
    monkeypatch.setattr('test.common_helper.CommonDatabaseMock.exists', lambda self, uid: True)
    with caplog.at_level(logging.DEBUG):
        mock_listener.post_processing('AnyID', None)
        assert 'entry exists: AnyID' in caplog.messages[-1]


class UnpackingLockMock:
    @staticmethod
    def unpacking_lock_is_set(_):
        return True


def test_delete_file_is_locked(mock_listener, caplog):
    mock_listener.unpacking_locks = UnpackingLockMock
    with caplog.at_level(logging.DEBUG):
        mock_listener.post_processing('AnyID', None)
        assert 'processed by unpacker: AnyID' in caplog.messages[-1]
