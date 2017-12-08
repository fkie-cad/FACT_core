import unittest.mock
from tempfile import TemporaryDirectory

from helperFunctions.config import get_config_for_testing
from storage.MongoMgr import MongoMgr
from test.common_helper import get_database_names
from test.unit.helperFunctions_setup_test_data import clean_test_database
from web_interface.frontend_main import WebFrontEnd

TMP_DIR = TemporaryDirectory(prefix='faf_test_')


class RestTestBase(unittest.TestCase):
    def setUp(self):
        self.config = get_config_for_testing(TMP_DIR)

        self.mongo_mgr = MongoMgr(self.config)

        self.frontend = WebFrontEnd(config=self.config)
        self.frontend.app.config['TESTING'] = True
        self.test_client = self.frontend.app.test_client()

    def tearDown(self):
        clean_test_database(self.config, get_database_names(self.config))
        self.mongo_mgr.shutdown()
