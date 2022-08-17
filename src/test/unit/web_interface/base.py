# pylint: disable=attribute-defined-outside-init
import gc
from tempfile import TemporaryDirectory
from unittest.mock import patch

from test.common_helper import CommonDatabaseMock, CommonIntercomMock, get_config_for_testing
from web_interface.frontend_main import WebFrontEnd
from web_interface.security.authentication import add_flask_security_to_app

INTERCOM = 'intercom.front_end_binding.InterComFrontEndBinding'
DB_INTERFACES = [
    'storage.db_interface_frontend.FrontEndDbInterface',
    'storage.db_interface_frontend_editing.FrontendEditingDbInterface',
    'storage.db_interface_comparison.ComparisonDbInterface',
    'storage.db_interface_stats.StatsDbViewer',
]


class FrontendDbMock:
    def __init__(self, db_mock: CommonDatabaseMock):
        self.frontend = db_mock
        self.editing = db_mock
        self.admin = db_mock
        self.comparison = db_mock
        self.template = db_mock
        self.stats_viewer = db_mock
        self.stats_updater = db_mock


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
    def setup_class(cls, db_mock=CommonDatabaseMock, intercom_mock=CommonIntercomMock):  # pylint: disable=arguments-differ
        cls.tmp_dir = TemporaryDirectory(prefix='fact_test_')  # pylint: disable=consider-using-with
        cls.config = get_config_for_testing(cls.tmp_dir)
        cls.db_mock = db_mock
        cls.intercom = intercom_mock
        cls._init_patches()
        cls.frontend = WebFrontEnd(config=cls.config, db=FrontendDbMock(db_mock()), intercom=intercom_mock)
        cls.frontend.app.config['TESTING'] = True
        cls.test_client = cls.frontend.app.test_client()

    def setup(self):
        self.intercom.tasks.clear()

    @classmethod
    def _init_patches(cls):
        cls.security_patch = patch(
            target='web_interface.frontend_main.add_flask_security_to_app',
            new=cls.add_security_get_mocked,
        )
        cls.security_patch.start()

    @classmethod
    def add_security_get_mocked(cls, app):
        add_flask_security_to_app(app)
        return UserDbMock(), cls.db_mock()

    @classmethod
    def teardown_class(cls):
        cls.security_patch.stop()
        cls.tmp_dir.cleanup()
        gc.collect()
