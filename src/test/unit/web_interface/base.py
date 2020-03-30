import gc
import unittest
import unittest.mock
from tempfile import TemporaryDirectory

from test.common_helper import DatabaseMock, fake_exit, get_config_for_testing
from web_interface.frontend_main import WebFrontEnd

TMP_DIR = TemporaryDirectory(prefix="fact_test_")


class WebInterfaceTest(unittest.TestCase):

    def setUp(self, db_mock=DatabaseMock):  # pylint: disable=arguments-differ
        self.mocked_interface = db_mock()

        self.enter_patch = unittest.mock.patch(target='helperFunctions.database.ConnectTo.__enter__', new=lambda _: self.mocked_interface)
        self.enter_patch.start()

        self.exit_patch = unittest.mock.patch(target='helperFunctions.database.ConnectTo.__exit__', new=fake_exit)
        self.exit_patch.start()

        self.config = get_config_for_testing(TMP_DIR)
        self.frontend = WebFrontEnd(config=self.config)
        self.frontend.app.config['TESTING'] = True
        self.test_client = self.frontend.app.test_client()

    def tearDown(self):
        self.enter_patch.stop()
        self.exit_patch.stop()

        self.mocked_interface.shutdown()
        gc.collect()
