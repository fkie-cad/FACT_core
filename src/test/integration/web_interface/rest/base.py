# pylint: disable=attribute-defined-outside-init,wrong-import-order
import pytest

from config import configparser_cfg
from web_interface.frontend_main import WebFrontEnd


@pytest.mark.usefixtures('patch_cfg')
class RestTestBase:

    @classmethod
    def setup_class(cls):
        cls.config = configparser_cfg

    def setup(self):
        self.frontend = WebFrontEnd(config=self.config)
        self.frontend.app.config['TESTING'] = True
        self.test_client = self.frontend.app.test_client()
