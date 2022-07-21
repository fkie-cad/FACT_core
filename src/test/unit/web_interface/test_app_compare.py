# pylint: disable=wrong-import-order
from flask import session

from test.common_helper import COMPARISON_ID, TEST_FW, TEST_FW_2
from test.unit.web_interface.base import WebInterfaceTest


class TestAppCompare(WebInterfaceTest):

    def test_add_firmwares_to_compare(self):
        with self.test_client:
            rv = self.test_client.get(f'/comparison/add/{TEST_FW.uid}', follow_redirects=True)
            assert 'Firmware Selected for Comparison' in rv.data.decode()
            assert 'uids_for_comparison' in session
            assert TEST_FW.uid in session['uids_for_comparison']

    def test_add_firmwares_to_compare__multiple(self):
        with self.test_client as tc:
            with tc.session_transaction() as test_session:
                test_session['uids_for_comparison'] = {TEST_FW_2.uid: None}
            rv = self.test_client.get(f'/comparison/add/{TEST_FW.uid}', follow_redirects=True)
            assert 'Remove All' in rv.data.decode()

    def test_start_compare(self):
        with self.test_client as tc:
            with tc.session_transaction() as test_session:
                test_session['uids_for_comparison'] = {'uid1': None, 'uid2': None}
            rv = self.test_client.get('/compare', follow_redirects=True)
            assert b'Your compare task is in progress' in rv.data
            assert len(self.intercom.tasks) == 1, 'task not added'
            assert self.intercom.tasks[0] == ('uid1;uid2', None), 'task not correct'

    def test_start_compare__force(self):
        with self.test_client as tc:
            with tc.session_transaction() as test_session:
                test_session['uids_for_comparison'] = {'uid1': None, 'uid2': None}
            rv = self.test_client.get('/compare?force_recompare=true', follow_redirects=True)
            assert b'Your compare task is in progress' in rv.data
            assert len(self.intercom.tasks) == 1, 'task not added'
            assert self.intercom.tasks[0] == ('uid1;uid2', True), 'task not correct'

    def test_start_compare__list_empty(self):
        rv = self.test_client.get('/compare', follow_redirects=True)
        assert b'No UIDs found for comparison' in rv.data

    def test_show_compare_result(self):
        rv = self.test_client.get(f'/compare/{COMPARISON_ID}', follow_redirects=True)
        assert b'General information' in rv.data
