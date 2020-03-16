import gc
import unittest
from tempfile import TemporaryDirectory

from storage.MongoMgr import MongoMgr
from test.common_helper import clean_test_database, get_config_for_testing, get_database_names
from web_interface.frontend_main import WebFrontEnd

TMP_DIR = TemporaryDirectory(prefix='fact_test_')


class RestTestBase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.config = get_config_for_testing(TMP_DIR)
        cls.mongo_mgr = MongoMgr(cls.config)

    def setUp(self):
        self.frontend = WebFrontEnd(config=self.config)
        self.frontend.app.config['TESTING'] = True
        self.test_client = self.frontend.app.test_client()

    def tearDown(self):
        clean_test_database(self.config, get_database_names(self.config))
        gc.collect()

    @classmethod
    def tearDownClass(cls):
        cls.mongo_mgr.shutdown()
