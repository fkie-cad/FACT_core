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
    @classmethod
    def setup_class(cls):
        pass

    def setup(self, db_mock=CommonDatabaseMock, intercom_mock=CommonIntercomMock):  # pylint: disable=arguments-differ
        self._init_patches(db_mock, intercom_mock)
        self.db_mock = db_mock
        self.intercom = intercom_mock
        self.tmp_dir = TemporaryDirectory(prefix='fact_test_')
        self.config = get_config_for_testing(self.tmp_dir)
        self.intercom.tasks.clear()
        self.frontend = WebFrontEnd(config=self.config)
        self.frontend.app.config['TESTING'] = True
        self.test_client = self.frontend.app.test_client()

    def _init_patches(self, db_mock, intercom_mock):
        self.patches = []
        for db_interface in DB_INTERFACES:
            self.patches.append(patch(f'{db_interface}.__init__', new=lambda *_, **__: None))
            self.patches.append(patch(f'{db_interface}.__new__', new=lambda *_, **__: db_mock()))
        self.patches.append(patch(f'{INTERCOM}.__init__', new=lambda *_, **__: None))
        self.patches.append(patch(f'{INTERCOM}.__new__', new=lambda *_, **__: intercom_mock()))
        self.patches.append(patch(
            target='web_interface.frontend_main.add_flask_security_to_app',
            new=self.add_security_get_mocked
        ))

        for patch_ in self.patches:
            patch_.start()

    def add_security_get_mocked(self, app):
        add_flask_security_to_app(app)
        return UserDbMock(), self.db_mock()

    def teardown(self):
        for patch_ in self.patches:
            patch_.stop()
        self.tmp_dir.cleanup()
        gc.collect()
