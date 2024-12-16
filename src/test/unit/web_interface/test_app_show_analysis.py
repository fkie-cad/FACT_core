from http import HTTPStatus

import pytest

from helperFunctions.data_conversion import make_bytes
from test.common_helper import (
    TEST_FW,
    TEST_FW_2,
    TEST_TEXT_FILE,
    CommonDatabaseMock,
    create_test_file_object,
    generate_analysis_entry,
)
from test.unit.conftest import CommonIntercomMock

FAILED_FO = create_test_file_object(
    uid='failed_uid',
    analyses={
        'failed_analysis': generate_analysis_entry(plugin_version='0.0', analysis_result={'failed': 'reason for fail'})
    },
)


class IntercomMock(CommonIntercomMock):
    def add_single_file_task(self, task):
        self.task_list.append(task)

    def get_available_analysis_plugins(self):
        plugins = super().get_available_analysis_plugins()
        plugins.update(
            {
                'failed_analysis': ('plugin description', False, {'default': True}, *self._common_fields),
            }
        )

        return plugins


class DbMock(CommonDatabaseMock):
    def get_object(self, uid, analysis_filter=None):
        if uid == FAILED_FO.uid:
            return FAILED_FO
        return super().get_object(uid, analysis_filter=analysis_filter)


@pytest.mark.WebInterfaceUnitTestConfig(intercom_mock_class=IntercomMock, database_mock_class=DbMock)
class TestAppShowAnalysis:
    def test_app_show_analysis_get_valid_fw(self, test_client):
        result = test_client.get(f'/analysis/{TEST_FW.uid}').data
        assert b'<strong>UID:</strong> ' + make_bytes(TEST_FW.uid) in result
        assert b'data-toggle="tooltip" title="mandatory plugin description"' in result
        assert b'data-toggle="tooltip" title="optional plugin description"' in result
        assert b'test text' in result, 'general info: file type is missing'

        # check release date not available
        assert b'1970-01-01' not in result
        assert b'unknown' in result

        result = test_client.get(f'/analysis/{TEST_FW_2.uid}').data
        assert b'unknown' not in result
        assert b'2000-01-01' in result

    def test_app_show_analysis_file_with_preview(self, test_client):
        result = test_client.get(f'/analysis/{TEST_TEXT_FILE.uid}').data
        assert b'<strong>UID:</strong> ' + make_bytes(TEST_TEXT_FILE.uid) in result
        assert b'Preview' in result

    def test_app_show_analysis_invalid_analysis(self, test_client):
        result = test_client.get(f'/analysis/{TEST_FW.uid}/this_analysis_does_not_exist/ro/{TEST_FW.uid}').data
        assert b'The requested analysis (this_analysis_does_not_exist) has not run (yet)' in result

    def test_app_single_file_analysis(self, test_client, intercom_task_list):
        result = test_client.get(f'/analysis/{TEST_FW.uid}')

        assert b'Add new analysis' in result.data
        assert b'Update analysis' in result.data

        assert not intercom_task_list
        post_new = test_client.post(
            f'/analysis/{TEST_FW.uid}',
            content_type='multipart/form-data',
            data={'analysis_systems': ['plugin_a', 'plugin_b']},
        )

        assert post_new.status_code == HTTPStatus.FOUND
        assert intercom_task_list
        assert intercom_task_list[0].scheduled_analysis == ['plugin_a', 'plugin_b']

    def test_app_failed_analysis(self, test_client):
        template = test_client.get(f'/analysis/{FAILED_FO.uid}/failed_analysis').data.decode()
        assert 'Failed' in template
        assert 'reason for fail' in template
        assert 'class="table-danger"' in template, 'failed result should be rendered in "danger" style'
