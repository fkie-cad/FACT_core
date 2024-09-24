from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from storage.db_interface_frontend import MetaEntry
from test.common_helper import TEST_FW_2, TEST_TEXT_FILE, CommonDatabaseMock, assert_search_result

if TYPE_CHECKING:
    from werkzeug.test import TestResponse


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
        assert_search_result(response, included=[TEST_FW_2], excluded=[TEST_TEXT_FILE])

    def test_advanced_search_firmware(self, test_client):
        response = _do_advanced_search(test_client, {'advanced_search': f'{{"_id": "{TEST_FW_2.uid}"}}'})
        assert_search_result(response, included=[TEST_FW_2], excluded=[TEST_TEXT_FILE])

    def test_advanced_search_file_object(self, test_client):
        response = _do_advanced_search(test_client, {'advanced_search': f'{{"_id": "{TEST_TEXT_FILE.uid}"}}'})
        assert_search_result(response, included=[TEST_TEXT_FILE], excluded=[TEST_FW_2])

    def test_advanced_search_only_firmwares(self, test_client):
        response = _do_advanced_search(
            test_client,
            {'advanced_search': f'{{"_id": "{TEST_TEXT_FILE.uid}"}}', 'only_firmwares': 'True'},
        )
        assert_search_result(response, included=[TEST_FW_2], excluded=[TEST_TEXT_FILE])


def _do_advanced_search(test_client, query: dict) -> TestResponse:
    return test_client.post(
        '/database/advanced_search',
        data=query,
        content_type='multipart/form-data',
        follow_redirects=True,
    )
