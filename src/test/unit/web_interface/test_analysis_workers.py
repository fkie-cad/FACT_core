import pytest

from test.unit.conftest import CommonIntercomMock


class IntercomMock(CommonIntercomMock):
    def set_plugin_process_count(self, plugin_process_count):
        self.task_list.append(('worker_count', plugin_process_count))


@pytest.mark.WebInterfaceUnitTestConfig(intercom_mock_class=IntercomMock)
class TestAnalysisWorkers:
    def test_get_lists_plugins(self, test_client):
        rv = test_client.get('/admin/analysis_workers')

        assert rv.status_code == 200
        assert b'default_plugin' in rv.data, 'analysis plugins should be listed on the page'
        assert b'1' in rv.data, 'current live worker count should be shown'

    def test_post_dispatches_single_worker_count_dict(self, test_client, intercom_task_list):
        rv = test_client.post('/admin/analysis_workers', data={'default_plugin': '3', 'mandatory_plugin': '2'})

        assert rv.status_code == 200
        assert intercom_task_list == [
            ('worker_count', {'default_plugin': 3, 'mandatory_plugin': 2}),
        ]

    def test_post_shows_requested_counts(self, test_client):
        rv = test_client.post('/admin/analysis_workers', data={'default_plugin': '3', 'mandatory_plugin': '2'})

        assert rv.status_code == 200
        assert b'name="default_plugin" value="3"' in rv.data, (
            'the newly requested worker count should be shown after the update'
        )

    def test_post_invalid_count_is_rejected(self, test_client, intercom_task_list):
        rv = test_client.post('/admin/analysis_workers', data={'default_plugin': 'not-a-number'})

        assert rv.status_code == 200
        assert intercom_task_list == [], 'an invalid worker count must not be forwarded'
        assert b'Invalid worker count' in rv.data
