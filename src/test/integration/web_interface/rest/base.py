# pylint: disable=attribute-defined-outside-init

import gc
from tempfile import TemporaryDirectory

from storage.MongoMgr import MongoMgr
from test.common_helper import clean_test_database, get_config_for_testing, get_database_names
from web_interface.frontend_main import WebFrontEnd


class RestTestBase:

    @classmethod
    def setup_class(cls):
        cls.tmp_dir = TemporaryDirectory(prefix='fact_test_')
        cls.config = get_config_for_testing(cls.tmp_dir)
        cls.mongo_mgr = MongoMgr(cls.config)

    def setup(self):
        self.frontend = WebFrontEnd(config=self.config)
        self.frontend.app.config['TESTING'] = True
        self.test_client = self.frontend.app.test_client()

    def teardown(self):
        clean_test_database(self.config, get_database_names(self.config))
        gc.collect()

    @classmethod
    def teardown_class(cls):
        cls.mongo_mgr.shutdown()
