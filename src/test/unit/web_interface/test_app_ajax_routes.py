import pytest

from test.common_helper import TEST_FW, TEST_FW_2
from test.unit.web_interface.base import WebInterfaceTest
from web_interface.components.ajax_routes import AjaxRoutes


class TestAppAjaxRoutes(WebInterfaceTest):

    def test_ajax_get_summary(self):
        result = self.test_client.get('/ajax_get_summary/{}/foobar'.format(TEST_FW.uid)).data
        assert b'Summary including results of included files' in result
        assert b'foobar' in result
        assert b'some_uid' in result

    def test_ajax_get_summary__summary_not_found(self):
        result = self.test_client.get('/ajax_get_summary/{}/not_found'.format(TEST_FW.uid)).data
        assert b'No summary found' in result

    def test_ajax_get_common_files_for_compare(self):
        result = self.test_client.get('/compare/ajax_common_files/{compare_id}/{feature_id}/'.format(
            compare_id='{};{}'.format(TEST_FW.uid, TEST_FW_2.uid), feature_id='some_feature___{}'.format(TEST_FW.uid)
        )).data.decode()
        assert TEST_FW.uid in result


@pytest.mark.parametrize('candidate, compare_id, expected_result', [
    ('all', 'uid1;uid2', 'uid1'),
    ('uid1', 'uid1;uid2', 'uid1'),
    ('uid2', 'uid1;uid2', 'uid2'),
    ('all', 'uid1', 'uid1'),
])
def test_get_root_uid(candidate, compare_id, expected_result):
    assert AjaxRoutes._get_root_uid(candidate, compare_id) == expected_result  # pylint: disable=protected-access
