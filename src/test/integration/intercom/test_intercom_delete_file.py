# pylint: disable=redefined-outer-name
import pytest

from intercom.back_end_binding import InterComBackEndDeleteFile
from test.common_helper import DatabaseMock, fake_exit, get_config_for_testing
from test.integration.common import MockFSOrganizer

LOGGING_OUTPUT = None


def set_output(message):
    global LOGGING_OUTPUT
    LOGGING_OUTPUT = message


@pytest.fixture(scope='function', autouse=True)
def mocking_the_database(monkeypatch):
    monkeypatch.setattr('helperFunctions.database.ConnectTo.__enter__', lambda _: DatabaseMock())
    monkeypatch.setattr('helperFunctions.database.ConnectTo.__exit__', fake_exit)
    monkeypatch.setattr('intercom.common_mongo_binding.InterComListener.__init__', lambda self, config: None)
    monkeypatch.setattr('logging.info', set_output)
    monkeypatch.setattr('logging.debug', set_output)


@pytest.fixture(scope='function')
def config():
    return get_config_for_testing()


@pytest.fixture(scope='function')
def mock_listener(config):
    listener = InterComBackEndDeleteFile(config)
    listener.fs_organizer = MockFSOrganizer(None)
    listener.config = config
    return listener


def test_delete_file_success(mock_listener):
    mock_listener.post_processing(dict(_id='AnyID'), None)
    assert LOGGING_OUTPUT == 'remove file: AnyID'


def test_delete_file_entry_exists(mock_listener, monkeypatch):
    monkeypatch.setattr('test.common_helper.DatabaseMock.existence_quick_check', lambda self, uid: True)
    mock_listener.post_processing(dict(_id='AnyID'), None)
    assert 'entry exists: AnyID' in LOGGING_OUTPUT


def test_delete_file_is_locked(mock_listener, monkeypatch):
    monkeypatch.setattr('test.common_helper.DatabaseMock.check_unpacking_lock', lambda self, uid: True)
    mock_listener.post_processing(dict(_id='AnyID'), None)
    assert 'processed by unpacker: AnyID' in LOGGING_OUTPUT
