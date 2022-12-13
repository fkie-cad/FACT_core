# pylint: disable=wrong-import-order
import pytest

from helperFunctions.data_conversion import normalize_compare_id
from test.common_helper import TEST_FW, TEST_FW_2, TEST_TEXT_FILE, CommonDatabaseMock
from test.mock import mock_patch


class DbMock(CommonDatabaseMock):
    @staticmethod
    def get_comparison_result(comparison_id):
        if comparison_id == normalize_compare_id(';'.join([TEST_FW.uid, TEST_FW_2.uid])):
            return {
                'this_is': 'a_compare_result',
                'general': {'hid': {TEST_FW.uid: 'foo', TEST_TEXT_FILE.uid: 'bar'}},
                'plugins': {'File_Coverage': {'some_feature': {TEST_FW.uid: [TEST_TEXT_FILE.uid]}}},
            }
        if comparison_id == normalize_compare_id(';'.join([TEST_FW.uid, TEST_TEXT_FILE.uid])):
            return {'this_is': 'a_compare_result'}
        return 'generic error'

    @staticmethod
    def get_statistic(identifier):
        if identifier == 'general':
            return {
                'number_of_firmwares': 1,
                'number_of_unique_files': 0,
                'total_firmware_size': 10,
                'total_file_size': 20,
                'average_firmware_size': 10,
                'average_file_size': 20,
                'benchmark': 61,
            }
        if identifier == 'release_date':
            return {'date_histogram_data': [['July 2014', 1]]}
        if identifier == 'backend':
            return {'system': {'cpu_percentage': 13.37}, 'analysis': {'current_analyses': [None, None]}}
        return None


@pytest.mark.WebInterfaceUnitTestConfig(dict(database_mock_class=DbMock))
class TestAppAjaxRoutes:
    def test_ajax_get_summary(self, test_client):
        result = test_client.get(f'/ajax_get_summary/{TEST_FW.uid}/foobar').data
        assert b'Summary including results of included files' in result
        assert b'foobar' in result
        assert b'some_uid' in result

    def test_ajax_get_summary__summary_not_found(self, test_client):
        result = test_client.get(f'/ajax_get_summary/{TEST_FW.uid}/not_found').data
        assert b'No summary found' in result

    def test_ajax_get_common_files_for_compare(self, test_client):
        url = f'/compare/ajax_common_files/{f"{TEST_FW.uid};{TEST_FW_2.uid}"}/{f"some_feature___{TEST_FW.uid}"}/'
        result = test_client.get(url).data.decode()
        assert TEST_FW.uid in result

    def test_ajax_get_system_stats(self, test_client):
        result = test_client.get('/ajax/stats/system').json

        assert result['backend_cpu_percentage'] == '13.37%'
        assert result['number_of_running_analyses'] == 2

    def test_ajax_get_system_stats_error(self, test_client):
        with mock_patch(DbMock, 'get_statistic', lambda *_: {}):
            result = test_client.get('/ajax/stats/system').json

        assert result['backend_cpu_percentage'] == 'n/a'
        assert result['number_of_running_analyses'] == 'n/a'

    def test_ajax_system_health(self, test_client):
        DbMock.get_stats_list = lambda *_: [{'foo': 'bar'}]
        result = test_client.get('/ajax/system_health').json
        assert 'systemHealth' in result
        assert result['systemHealth'] == [{'foo': 'bar'}]

    def test_ajax_get_hex_preview(self, test_client):
        DbMock.peek_in_binary = lambda *_: b'foobar'
        result = test_client.get('/ajax_get_hex_preview/some_uid/0/10')
        assert result.data.startswith(b'<pre')
        assert b'foobar' in result.data
