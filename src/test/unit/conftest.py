from typing import Type

import pytest
from pydantic import BaseModel

from test.common_helper import TEST_FW, TEST_TEXT_FILE, CommonDatabaseMock
from test.conftest import merge_markers
from web_interface.frontend_main import WebFrontEnd
from web_interface.security.authentication import add_flask_security_to_app


class CommonIntercomMock:
    task_list = None

    def __init__(self, *_, **__):
        pass

    @staticmethod
    def get_available_analysis_plugins():
        common_fields = ('0.0.', [], [], [], 1)
        return {
            'default_plugin': ('default plugin description', False, {'default': True}, *common_fields),
            'mandatory_plugin': ('mandatory plugin description', True, {'default': False}, *common_fields),
            'optional_plugin': ('optional plugin description', False, {'default': False}, *common_fields),
            'file_type': ('file_type plugin', False, {'default': False}, *common_fields),
            'unpacker': ('Additional information provided by the unpacker', True, False),
        }

    def shutdown(self):
        pass

    @staticmethod
    def peek_in_binary(*_):
        return b'foobar'

    @staticmethod
    def get_binary_and_filename(uid):
        if uid == TEST_FW.uid:
            return TEST_FW.binary, TEST_FW.file_name
        if uid == TEST_TEXT_FILE.uid:
            return TEST_TEXT_FILE.binary, TEST_TEXT_FILE.file_name
        return None

    @staticmethod
    def get_repacked_binary_and_file_name(uid):
        if uid == TEST_FW.uid:
            return TEST_FW.binary, f'{TEST_FW.file_name}.tar.gz'
        return None, None

    @staticmethod
    def add_binary_search_request(*_):
        return 'binary_search_id'

    @staticmethod
    def get_binary_search_result(uid):
        if uid == 'binary_search_id':
            return {'test_rule': ['test_uid']}, b'some yara rule'
        return None, None

    def add_compare_task(self, compare_id, force=False):
        self.task_list.append((compare_id, force))

    def add_analysis_task(self, task):
        self.task_list.append(task)

    def add_re_analyze_task(self, task, unpack=True):
        self.task_list.append(task)


class FrontendDatabaseMock:
    """A class mocking :py:class:`~web_interface.frontend_database.FrontendDatabase`."""

    def __init__(self, db_mock: CommonDatabaseMock):
        """
        The Constructor.

        :param db_mock: An object providing every function needed for a test.
        """
        self.frontend = db_mock
        self.editing = db_mock
        self.admin = db_mock
        self.comparison = db_mock
        self.template = db_mock
        self.stats_viewer = db_mock
        self.stats_updater = db_mock


class _UserDbMock:
    class session:  # noqa: N801
        @staticmethod
        def commit():
            pass

        @staticmethod
        def rollback():
            pass


class StatusInterfaceMock:
    def __init__(self):
        self._status = None

    def set_analysis_status(self, status: dict):
        self._status = status

    def get_analysis_status(self):
        return self._status


class WebInterfaceUnitTestConfig(BaseModel):
    """A class configuring the :py:func:`web_frontend` fixture."""

    #: A class that can be instanced to mock every ``@property`` of
    #: :py:class:`~web_interface.frontend_database.FrontendDatabase`.
    #: See also: The documentation of :py:class:`FrontendDatabaseMock`
    database_mock_class: Type = CommonDatabaseMock
    #: A class mocking :py:class:`~intercom.front_end_binding.InterComFrontEndBinding`
    intercom_mock_class: Type[CommonIntercomMock] = CommonIntercomMock
    #: A class mocking :py:class:`~intercom.front_end_binding.InterComFrontEndBinding`
    redis_mock_class: Type[StatusInterfaceMock] = StatusInterfaceMock


@pytest.fixture
def intercom_task_list() -> list:
    """A fixture used to add tasks in the :py:class:`CommonIntercomMock`.
    It can be used to inspect what tasks where added"""
    return []


@pytest.fixture
def web_frontend(request, monkeypatch, intercom_task_list) -> WebFrontEnd:
    """Returns an instance of :py:class:`~web_interface.frontend_main.WebFrontEnd`.
    This fixture can be configured by providing an instance of :py:class:`WebInterfaceUnitTestConfig` as a marker
    called ``WebInterfaceUnitTestConfig``.

    .. seealso::

        The fixture :py:func:`intercom_task_list`.
    """
    test_config = merge_markers(request, 'WebInterfaceUnitTestConfig', WebInterfaceUnitTestConfig)

    db_mock_instance = test_config.database_mock_class()
    IntercomMockClass = test_config.intercom_mock_class  # noqa: N806

    def _add_flask_security_to_app_mock(app):
        add_flask_security_to_app(app)
        return _UserDbMock(), db_mock_instance

    monkeypatch.setattr('web_interface.frontend_main.add_flask_security_to_app', _add_flask_security_to_app_mock)

    monkeypatch.setattr(IntercomMockClass, 'task_list', intercom_task_list)
    # Note: The intercom argument is only the class. It gets instanced when intercom access in needed by `ConnectTo`.
    frontend = WebFrontEnd(
        db=FrontendDatabaseMock(db_mock_instance),
        intercom=IntercomMockClass,
        status_interface=test_config.redis_mock_class(),
    )
    frontend.app.config['TESTING'] = True

    return frontend


@pytest.fixture
def test_client(web_frontend):
    """Shorthand for ``web_frontend.app.test_client``"""
    return web_frontend.app.test_client()
