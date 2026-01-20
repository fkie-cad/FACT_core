import pytest

from storage.db_interface_frontend import MetaEntry
from test.common_helper import TEST_FW_2, CommonDatabaseMock


class DbMock(CommonDatabaseMock):
    @staticmethod
    def generic_search(
        search_dict: dict,
        skip: int = 0,  # noqa: ARG004
        limit: int = 0,  # noqa: ARG004
        only_fo_parent_firmware: bool = False,  # noqa: ARG004
        inverted: bool = False,  # noqa: ARG004
        as_meta: bool = False,
    ):
        result = []
        if search_dict.get('$or', {}).get('file_name', {}).get('$like') == TEST_FW_2.file_name:  # noqa: SIM114
            result.append(TEST_FW_2.uid)
        elif search_dict.get('$or', {}).get('device_name', {}).get('$like') == TEST_FW_2.device_name:  # noqa: SIM114
            result.append(TEST_FW_2.uid)
        elif search_dict.get('$or', {}).get('vendor', {}).get('$like') == TEST_FW_2.vendor:  # noqa: SIM114
            result.append(TEST_FW_2.uid)
        elif search_dict.get('$or', {}).get('sha256') == TEST_FW_2.sha256:  # noqa: SIM114
            result.append(TEST_FW_2.uid)
        elif search_dict.get('$or', {}).get('firmware_tags') in TEST_FW_2.tags:
            result.append(TEST_FW_2.uid)

        if as_meta:
            return [MetaEntry(uid, 'hid', {}, 0) for uid in result]
        return result

    def get_object(self, uid: str, analysis_filter=None):
        if uid == TEST_FW_2.uid:
            return TEST_FW_2
        return None


@pytest.mark.frontend_config_overwrite(
    {
        'results_per_page': 10,
    }
)
@pytest.mark.WebInterfaceUnitTestConfig(database_mock_class=DbMock)
class TestAppQuickSearch:
    def test_quick_search_file_name(self, test_client):
        assert TEST_FW_2.uid in _start_quick_search(test_client, TEST_FW_2.file_name)

    def test_quick_search_device_name(self, test_client):
        assert TEST_FW_2.uid in _start_quick_search(test_client, TEST_FW_2.device_name)

    def test_quick_search_vendor(self, test_client):
        assert TEST_FW_2.uid in _start_quick_search(test_client, TEST_FW_2.vendor)

    def test_quick_search_sha256(self, test_client):
        assert TEST_FW_2.uid in _start_quick_search(test_client, TEST_FW_2.sha256)

    def test_quick_search_uid(self, test_client):
        response = _start_quick_search(test_client, TEST_FW_2.uid)
        assert TEST_FW_2.uid in response
        assert 'Analysis Results' in response  # this should lead directly to the analysis page

    def test_quick_search_tags(self, test_client):
        assert TEST_FW_2.uid in _start_quick_search(test_client, list(TEST_FW_2.tags)[0])


def _start_quick_search(test_client, search_term):
    response = test_client.get(
        '/database/quick_search', query_string={'search_term': search_term}, follow_redirects=True
    )
    return response.data.decode()
