import gc
import unittest
import unittest.mock
from tempfile import TemporaryDirectory

from helperFunctions.config import get_config_for_testing
from test.common_helper import DatabaseMock, fake_exit
from web_interface.frontend_main import WebFrontEnd

TMP_DIR = TemporaryDirectory(prefix="fact_test_")


class WebInterfaceTest(unittest.TestCase):

    def setUp(self):
        self.mocked_interface = DatabaseMock()

        self.enter_patch = unittest.mock.patch(target='helperFunctions.web_interface.ConnectTo.__enter__', new=lambda _: self.mocked_interface)
        self.enter_patch.start()

        self.exit_patch = unittest.mock.patch(target='helperFunctions.web_interface.ConnectTo.__exit__', new=fake_exit)
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
