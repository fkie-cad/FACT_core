# pylint: disable=attribute-defined-outside-init
import gc
from tempfile import TemporaryDirectory
from unittest import mock

from test.common_helper import CommonDatabaseMock, CommonIntercomMock, get_config_for_testing

INTERCOM = 'intercom.front_end_binding.InterComFrontEndBinding'
DB_INTERFACES = [
    'storage_postgresql.db_interface_frontend.FrontEndDbInterface',
    'storage_postgresql.db_interface_frontend_editing.FrontendEditingDbInterface',
    'storage_postgresql.db_interface_comparison.ComparisonDbInterface',
    'storage_postgresql.db_interface_stats.StatsDbViewer',
]


class WebInterfaceTest:

    def setup(self, db_mock=CommonDatabaseMock, intercom_mock=CommonIntercomMock):  # pylint: disable=arguments-differ
        self._init_patches(db_mock, intercom_mock)
        # delay import to be able to mock the database before the frontend imports it -- weird hack but OK
        from web_interface.frontend_main import WebFrontEnd  # pylint: disable=import-outside-toplevel

        self.tmp_dir = TemporaryDirectory(prefix='fact_test_')
        self.config = get_config_for_testing(self.tmp_dir)
        self.intercom = intercom_mock
        self.intercom.tasks.clear()
        self.frontend = WebFrontEnd(config=self.config)
        self.frontend.app.config['TESTING'] = True
        self.test_client = self.frontend.app.test_client()

    def _init_patches(self, db_mock, intercom_mock):
        self.patches = [
            mock.patch(db_interface, db_mock)
            for db_interface in DB_INTERFACES
        ]
        self.patches.append(mock.patch(INTERCOM, intercom_mock))

        for patch in self.patches:
            patch.start()

    def teardown(self):
        for patch in self.patches:
            patch.stop()
        self.tmp_dir.cleanup()
        gc.collect()
