# pylint: disable=wrong-import-order
from flask import session

from test.common_helper import COMPARISON_ID, TEST_FW, TEST_FW_2


def test_add_firmwares_to_compare(test_client):
    with test_client:
        rv = test_client.get(f'/comparison/add/{TEST_FW.uid}', follow_redirects=True)
        assert 'Firmware Selected for Comparison' in rv.data.decode()
        assert 'uids_for_comparison' in session
        assert TEST_FW.uid in session['uids_for_comparison']


def test_add_firmwares_to_compare__multiple(test_client):
    with test_client as tc:
        with tc.session_transaction() as test_session:
            test_session['uids_for_comparison'] = {TEST_FW_2.uid: None}
        rv = test_client.get(f'/comparison/add/{TEST_FW.uid}', follow_redirects=True)
        assert 'Remove All' in rv.data.decode()


def test_start_compare(test_client, intercom_task_list):
    with test_client as tc:
        with tc.session_transaction() as test_session:
            test_session['uids_for_comparison'] = {'uid1': None, 'uid2': None}
        rv = test_client.get('/compare', follow_redirects=True)
        assert b'Your compare task is in progress' in rv.data
        assert len(intercom_task_list) == 1, 'task not added'
        assert intercom_task_list[0] == ('uid1;uid2', None), 'task not correct'


def test_start_compare__force(test_client, intercom_task_list):
    with test_client as tc:
        with tc.session_transaction() as test_session:
            test_session['uids_for_comparison'] = {'uid1': None, 'uid2': None}
        rv = test_client.get('/compare?force_recompare=true', follow_redirects=True)
        assert b'Your compare task is in progress' in rv.data
        assert len(intercom_task_list) == 1, 'task not added'
        assert intercom_task_list[0] == ('uid1;uid2', True), 'task not correct'


def test_start_compare__list_empty(test_client):
    rv = test_client.get('/compare', follow_redirects=True)
    assert b'No UIDs found for comparison' in rv.data


def test_show_compare_result(test_client):
    rv = test_client.get(f'/compare/{COMPARISON_ID}', follow_redirects=True)
    assert b'General information' in rv.data
