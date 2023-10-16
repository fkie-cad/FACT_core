from web_interface.frontend_main import WebFrontEnd


class RestTestBase:
    def setup_method(self):
        self.frontend = WebFrontEnd()
        self.frontend.app.config['TESTING'] = True
        self.test_client = self.frontend.app.test_client()
