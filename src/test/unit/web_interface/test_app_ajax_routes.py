# pylint: disable=wrong-import-order

import pytest

from test.common_helper import TEST_FW, TEST_FW_2
from test.mock import mock_patch
from test.unit.web_interface.base import WebInterfaceTest
from web_interface.components.ajax_routes import AjaxRoutes


class TestAppAjaxRoutes(WebInterfaceTest):

    def test_ajax_get_summary(self):
        result = self.test_client.get(f'/ajax_get_summary/{TEST_FW.uid}/foobar').data
        assert b'Summary including results of included files' in result
        assert b'foobar' in result
        assert b'some_uid' in result

    def test_ajax_get_summary__summary_not_found(self):
        result = self.test_client.get(f'/ajax_get_summary/{TEST_FW.uid}/not_found').data
        assert b'No summary found' in result

    def test_ajax_get_common_files_for_compare(self):
        url = f'/compare/ajax_common_files/{f"{TEST_FW.uid};{TEST_FW_2.uid}"}/{f"some_feature___{TEST_FW.uid}"}/'
        result = self.test_client.get(url).data.decode()
        assert TEST_FW.uid in result

    def test_ajax_get_system_stats(self):
        result = self.test_client.get('/ajax/stats/system').json

        assert result['backend_cpu_percentage'] == '13.37%'
        assert result['number_of_running_analyses'] == 2

    def test_ajax_get_system_stats_error(self):
        with mock_patch(self.mocked_interface, 'get_statistic', lambda _: {}):
            result = self.test_client.get('/ajax/stats/system').json

        assert result['backend_cpu_percentage'] == 'n/a'
        assert result['number_of_running_analyses'] == 'n/a'

    def test_ajax_system_health(self):
        self.mocked_interface.get_stats_list = lambda *_: [{'foo': 'bar'}]
        result = self.test_client.get('/ajax/system_health').json
        assert 'systemHealth' in result
        assert result['systemHealth'] == [{'foo': 'bar'}]


@pytest.mark.parametrize('candidate, compare_id, expected_result', [
    ('all', 'uid1;uid2', 'uid1'),
    ('uid1', 'uid1;uid2', 'uid1'),
    ('uid2', 'uid1;uid2', 'uid2'),
    ('all', 'uid1', 'uid1'),
])
def test_get_root_uid(candidate, compare_id, expected_result):
    assert AjaxRoutes._get_root_uid(candidate, compare_id) == expected_result  # pylint: disable=protected-access
