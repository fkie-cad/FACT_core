import gc

import pytest

from test.common_helper import TestBase, clean_test_database, get_database_names
from web_interface.frontend_main import WebFrontEnd


@pytest.mark.usefixtures('start_db')
class RestTestBase(TestBase):
    def setup(self):
        self.frontend = WebFrontEnd(config=self.config)
        self.frontend.app.config['TESTING'] = True
        self.test_client = self.frontend.app.test_client()

    def teardown(self):
        clean_test_database(self.config, get_database_names(self.config))
        gc.collect()
