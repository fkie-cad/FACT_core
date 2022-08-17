# pylint: disable=wrong-import-order
from storage.db_interface_frontend import MetaEntry
from test.common_helper import TEST_FW_2, CommonDatabaseMock
from test.unit.web_interface.base import WebInterfaceTest


class DbMock(CommonDatabaseMock):
    @staticmethod
    def generic_search(
        search_dict: dict,
        skip: int = 0,
        limit: int = 0,  # pylint: disable=unused-argument
        only_fo_parent_firmware: bool = False,
        inverted: bool = False,
        as_meta: bool = False
    ):  # pylint: disable=unused-argument
        result = []
        if search_dict.get('$or', {}).get('file_name', {}).get('$like') == TEST_FW_2.file_name:
            result.append(TEST_FW_2.uid)
        elif search_dict.get('$or', {}).get('device_name', {}).get('$like') == TEST_FW_2.device_name:
            result.append(TEST_FW_2.uid)
        elif search_dict.get('$or', {}).get('vendor', {}).get('$like') == TEST_FW_2.vendor:
            result.append(TEST_FW_2.uid)
        elif search_dict.get('$or', {}).get('sha256') == TEST_FW_2.sha256:
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


class TestAppQuickSearch(WebInterfaceTest):
    @classmethod
    def setup_class(cls, *_, **__):
        super().setup_class(db_mock=DbMock)
        cls.config['database'] = {}
        cls.config['database']['results-per-page'] = '10'

    def test_quick_search_file_name(self):
        assert TEST_FW_2.uid in self._start_quick_search(TEST_FW_2.file_name)

    def test_quick_search_device_name(self):
        assert TEST_FW_2.uid in self._start_quick_search(TEST_FW_2.device_name)

    def test_quick_search_vendor(self):
        assert TEST_FW_2.uid in self._start_quick_search(TEST_FW_2.vendor)

    def test_quick_search_sha256(self):
        assert TEST_FW_2.uid in self._start_quick_search(TEST_FW_2.sha256)

    def test_quick_search_tags(self):
        assert TEST_FW_2.uid in self._start_quick_search(list(TEST_FW_2.tags)[0])

    def _start_quick_search(self, search_term):
        response = self.test_client.get(
            '/database/quick_search', query_string={'search_term': search_term}, follow_redirects=True
        )
        return response.data.decode()
