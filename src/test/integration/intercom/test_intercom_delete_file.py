# pylint: disable=redefined-outer-name,wrong-import-order
import logging

import pytest

from intercom.back_end_binding import InterComBackEndDeleteFile
from test.common_helper import CommonDatabaseMock, get_config_for_testing
from test.integration.common import MockFSOrganizer


@pytest.fixture(scope='function')
def config():
    return get_config_for_testing()


class UnpackingLockMock:
    @staticmethod
    def unpacking_lock_is_set(uid):
        if uid == 'locked':
            return True
        return False


@pytest.fixture(scope='function')
def mock_listener(config):
    listener = InterComBackEndDeleteFile(config, unpacking_locks=UnpackingLockMock(), db_interface=CommonDatabaseMock())
    listener.fs_organizer = MockFSOrganizer(None)
    listener.config = config
    return listener


def test_delete_file_success(mock_listener, caplog):
    with caplog.at_level(logging.INFO):
        mock_listener.post_processing(['AnyID'], None)
        assert 'removing file: AnyID' in caplog.messages


def test_delete_file_entry_exists(mock_listener, monkeypatch, caplog):
    monkeypatch.setattr('test.common_helper.CommonDatabaseMock.exists', lambda self, uid: True)
    with caplog.at_level(logging.DEBUG):
        mock_listener.post_processing(['AnyID'], None)
        assert 'entry exists: AnyID' in caplog.messages[-1]


def test_delete_file_is_locked(mock_listener, caplog):
    with caplog.at_level(logging.DEBUG):
        mock_listener.post_processing(['locked'], None)
        assert 'processed by unpacker: locked' in caplog.messages[-1]
