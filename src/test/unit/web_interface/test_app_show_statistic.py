import unittest.mock

from test.unit.web_interface.base import WebInterfaceTest


class TestShowStatistic(WebInterfaceTest):

    @unittest.mock.patch('test.common_helper.DatabaseMock.get_statistic', lambda self, identifier: None)
    def test_no_stats_available(self):
        rv = self.test_client.get('/statistic')
        assert b'General' not in rv.data
        assert b'<strong>No statistics available!</strong>' in rv.data

    def test_stats_available(self):
        rv = self.test_client.get('/statistic')
        assert b'General' in rv.data
        assert b'>1</td>'
