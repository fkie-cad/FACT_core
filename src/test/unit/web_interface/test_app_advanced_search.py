import pytest

from storage.db_interface_frontend import MetaEntry
from test.common_helper import TEST_FW_2, TEST_TEXT_FILE, CommonDatabaseMock


class DbMock(CommonDatabaseMock):
    @staticmethod
    def generic_search(
        search_dict: dict,
        skip: int = 0,  # noqa: ARG004
        limit: int = 0,  # noqa: ARG004
        only_fo_parent_firmware: bool = False,
        inverted: bool = False,  # noqa: ARG004
        as_meta: bool = False,
    ):
        result = []
        if TEST_FW_2.uid in str(search_dict) or search_dict == {}:
            result.append(TEST_FW_2.uid)
        if TEST_TEXT_FILE.uid in str(search_dict):
            if not only_fo_parent_firmware:
                result.append(TEST_TEXT_FILE.uid)
            elif TEST_FW_2.uid not in result:
                result.append(TEST_FW_2.uid)
        if as_meta:
            return [MetaEntry(uid, 'hid', {}, 0) for uid in result]
        return result


@pytest.mark.frontend_config_overwrite(
    {
        'results_per_page': 10,
    }
)
@pytest.mark.WebInterfaceUnitTestConfig(database_mock_class=DbMock)
class TestAppAdvancedSearch:
    def test_advanced_search(self, test_client):
        response = _do_advanced_search(test_client, {'advanced_search': '{}'})
        assert TEST_FW_2.uid in response
        assert TEST_TEXT_FILE.uid not in response

    def test_advanced_search_firmware(self, test_client):
        response = _do_advanced_search(test_client, {'advanced_search': f'{{"_id": "{TEST_FW_2.uid}"}}'})
        assert TEST_FW_2.uid in response
        assert TEST_TEXT_FILE.uid not in response

    def test_advanced_search_file_object(self, test_client):
        response = _do_advanced_search(test_client, {'advanced_search': f'{{"_id": "{TEST_TEXT_FILE.uid}"}}'})
        assert TEST_FW_2.uid not in response
        assert TEST_TEXT_FILE.uid in response

    def test_advanced_search_only_firmwares(self, test_client):
        response = _do_advanced_search(
            test_client,
            {'advanced_search': f'{{"_id": "{TEST_TEXT_FILE.uid}"}}', 'only_firmwares': 'True'},
        )
        assert TEST_FW_2.uid in response
        assert TEST_TEXT_FILE.uid not in response


def _do_advanced_search(test_client, query: dict) -> str:
    return test_client.post(
        '/database/advanced_search', data=query, content_type='multipart/form-data', follow_redirects=True
    ).data.decode()
