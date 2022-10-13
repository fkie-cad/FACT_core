# pylint: disable=attribute-defined-outside-init,wrong-import-order

from tempfile import TemporaryDirectory

from test.common_helper import get_config_for_testing
from web_interface.frontend_main import WebFrontEnd


class RestTestBase:

    @classmethod
    def setup_class(cls):
        cls.tmp_dir = TemporaryDirectory(prefix='fact_test_')
        cls.config = get_config_for_testing(cls.tmp_dir)

    def setup(self):
        self.frontend = WebFrontEnd(config=self.config)
        self.frontend.app.config['TESTING'] = True
        self.test_client = self.frontend.app.test_client()
