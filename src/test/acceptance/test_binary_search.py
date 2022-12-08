import pytest
from test.acceptance.conftest import SchedulerAcceptanceTestConfig, upload_test_firmware


query = {
    'file': None,
    'textarea': 'rule test_file_string {strings: $a = "This is the second test file" condition: $a }',
}


def _query_page_get(test_client):
    rv = test_client.get('/database/binary_search')
    assert b'<h3 class="mb-3">Binary Pattern Search</h3>' in rv.data


def _query_page_post_file_query(test_client):
    rv = test_client.post(
        '/database/binary_search', content_type='multipart/form-data', data=query, follow_redirects=True
    )
    assert b'testfile2' in rv.data


def _query_page_post_firmware_query(test_client, test_fw_a):
    rv = test_client.post(
        '/database/binary_search',
        content_type='multipart/form-data',
        data={**query, 'only_firmware': 'True'},
        follow_redirects=True,
    )
    assert test_fw_a.name.encode() in rv.data
    assert b'testfile2' not in rv.data


def _get_without_request_id(test_client):
    rv = test_client.get('/database/binary_search_results')
    assert b'No request ID found' in rv.data


@pytest.mark.skip(reason="TODO should work")
@pytest.mark.SchedulerTestConfig(
    SchedulerAcceptanceTestConfig(
        # 4 Files and 2 plugins
        items_to_analyze=4*2,
    ),
)
def test_binary_search(test_client, test_fw_a, analysis_finished_event):
    _query_page_get(test_client)
    upload_test_firmware(test_client, test_fw_a)
    analysis_finished_event.wait(timeout=15)
    _query_page_post_file_query(test_client)
    _query_page_post_firmware_query(test_client)
    _get_without_request_id(test_client)
