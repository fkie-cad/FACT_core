from test.common_helper import TEST_FW
from test.unit.web_interface.base import WebInterfaceTest


class TestAppAjaxRoutes(WebInterfaceTest):

    def test_ajax_get_summary(self):
        result = self.test_client.get('/ajax_get_summary/{}/foobar'.format(TEST_FW.uid)).data
        assert b'Summary Including Results of Included Files' in result
        assert b'foobar' in result
        assert b'some_uid' in result

    def test_ajax_get_summary__summary_not_found(self):
        result = self.test_client.get('/ajax_get_summary/{}/not_found'.format(TEST_FW.uid)).data
        assert b'no summary found' in result
