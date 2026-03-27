import logging

import pytest

from intercom.back_end_binding import InterComBackEndDeleteFile
from test.common_helper import CommonDatabaseMock
from test.integration.common import MockFileService


class UnpackingLockMock:
    @staticmethod
    def unpacking_lock_is_set(uid):
        if uid == 'locked':
            return True
        return False


@pytest.fixture
def mock_listener():
    listener = InterComBackEndDeleteFile(unpacking_locks=UnpackingLockMock(), db_interface=CommonDatabaseMock())
    listener.file_service = MockFileService()
    return listener


def test_delete_file_success(mock_listener, caplog):
    with caplog.at_level(logging.INFO):
        mock_listener.pre_process({'AnyID'}, None)
        assert 'Deleted 1 file(s)' in caplog.messages


def test_delete_file_entry_exists(mock_listener, monkeypatch, caplog):
    monkeypatch.setattr('test.common_helper.CommonDatabaseMock.uid_list_exists', lambda _, uid_list: set(uid_list))
    with caplog.at_level(logging.DEBUG):
        mock_listener.pre_process({'AnyID'}, None)
        assert 'entry exists: AnyID' in caplog.messages[-1]


def test_delete_file_is_locked(mock_listener, caplog):
    with caplog.at_level(logging.DEBUG):
        mock_listener.pre_process({'locked'}, None)
        assert 'processed by unpacker: locked' in caplog.messages[-1]
