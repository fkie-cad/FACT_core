# pylint: disable=wrong-import-order
import pytest

from storage.db_interface_frontend import MetaEntry
from test.common_helper import TEST_FW_2, TEST_TEXT_FILE, CommonDatabaseMock
from test.unit.web_interface.base import WebInterfaceTest


class DbMock(CommonDatabaseMock):
    @staticmethod
    def generic_search(
        search_dict: dict,
        skip: int = 0,
        limit: int = 0,  # pylint: disable=unused-argument
        only_fo_parent_firmware: bool = False,
        inverted: bool = False,
        as_meta: bool = False,
    ):  # pylint: disable=unused-argument
        result = []
        if TEST_FW_2.uid in str(search_dict) or search_dict == {}:
            result.append(TEST_FW_2.uid)
        if TEST_TEXT_FILE.uid in str(search_dict):
            if not only_fo_parent_firmware:
                result.append(TEST_TEXT_FILE.uid)
            else:
                if TEST_FW_2.uid not in result:
                    result.append(TEST_FW_2.uid)
        if as_meta:
            return [MetaEntry(uid, 'hid', {}, 0) for uid in result]
        return result


@pytest.mark.cfg_defaults(
    {
        'database': {
            'results-per-page': 10,
        },
    }
)
class TestAppAdvancedSearch(WebInterfaceTest):
    @classmethod
    def setup_class(cls, *_, **__):
        super().setup_class(db_mock=DbMock)

    def test_advanced_search(self):
        response = self._do_advanced_search({'advanced_search': '{}'})
        assert TEST_FW_2.uid in response
        assert TEST_TEXT_FILE.uid not in response

    def test_advanced_search_firmware(self):
        response = self._do_advanced_search({'advanced_search': f'{{"_id": "{TEST_FW_2.uid}"}}'})
        assert TEST_FW_2.uid in response
        assert TEST_TEXT_FILE.uid not in response

    def test_advanced_search_file_object(self):
        response = self._do_advanced_search({'advanced_search': f'{{"_id": "{TEST_TEXT_FILE.uid}"}}'})
        assert TEST_FW_2.uid not in response
        assert TEST_TEXT_FILE.uid in response

    def test_advanced_search_only_firmwares(self):
        response = self._do_advanced_search(
            {'advanced_search': f'{{"_id": "{TEST_TEXT_FILE.uid}"}}', 'only_firmwares': 'True'}
        )
        assert TEST_FW_2.uid in response
        assert TEST_TEXT_FILE.uid not in response

    def _do_advanced_search(self, query: dict) -> str:
        return self.test_client.post(
            '/database/advanced_search', data=query, content_type='multipart/form-data', follow_redirects=True
        ).data.decode()
