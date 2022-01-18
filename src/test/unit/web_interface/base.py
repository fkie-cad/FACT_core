# pylint: disable=attribute-defined-outside-init
import gc
from tempfile import TemporaryDirectory
from unittest.mock import patch

from test.common_helper import CommonDatabaseMock, CommonIntercomMock, get_config_for_testing
from web_interface.frontend_main import WebFrontEnd
from web_interface.security.authentication import add_flask_security_to_app

INTERCOM = 'intercom.front_end_binding.InterComFrontEndBinding'
DB_INTERFACES = [
    'storage_postgresql.db_interface_frontend.FrontEndDbInterface',
    'storage_postgresql.db_interface_frontend_editing.FrontendEditingDbInterface',
    'storage_postgresql.db_interface_comparison.ComparisonDbInterface',
    'storage_postgresql.db_interface_stats.StatsDbViewer',
]


class UserDbMock:
    class session:  # pylint: disable=invalid-name
        @staticmethod
        def commit():
            pass

        @staticmethod
        def rollback():
            pass


class WebInterfaceTest:
    patches = []

    @classmethod
    def setup_class(cls, db_mock=CommonDatabaseMock, intercom_mock=CommonIntercomMock):
        cls.tmp_dir = TemporaryDirectory(prefix='fact_test_')
        cls.config = get_config_for_testing(cls.tmp_dir)
        cls.db_mock = db_mock
        cls.intercom = intercom_mock
        cls._init_patches(db_mock, intercom_mock)
        cls.frontend = WebFrontEnd(config=cls.config)
        cls.frontend.app.config['TESTING'] = True
        cls.test_client = cls.frontend.app.test_client()

    def setup(self):  # pylint: disable=arguments-differ
        self.intercom.tasks.clear()

    @classmethod
    def _init_patches(cls, db_mock, intercom_mock):
        for db_interface in DB_INTERFACES:
            cls.patches.append(patch(f'{db_interface}.__init__', new=lambda *_, **__: None))
            cls.patches.append(patch(f'{db_interface}.__new__', new=lambda *_, **__: db_mock()))
        cls.patches.append(patch(f'{INTERCOM}.__init__', new=lambda *_, **__: None))
        cls.patches.append(patch(f'{INTERCOM}.__new__', new=lambda *_, **__: intercom_mock()))
        cls.patches.append(patch(
            target='web_interface.frontend_main.add_flask_security_to_app',
            new=cls.add_security_get_mocked
        ))
        for patch_ in cls.patches:
            patch_.start()

    @classmethod
    def add_security_get_mocked(cls, app):
        add_flask_security_to_app(app)
        return UserDbMock(), cls.db_mock()

    def teardown_class(self):
        for patch_ in self.patches:
            patch_.stop()
        self.tmp_dir.cleanup()
        gc.collect()
