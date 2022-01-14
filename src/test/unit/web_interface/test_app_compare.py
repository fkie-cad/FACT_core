# pylint: disable=wrong-import-order
from flask import session

from test.common_helper import TEST_FW, TEST_FW_2, CommonDatabaseMock, CommonIntercomMock
from test.unit.web_interface.base import WebInterfaceTest

COMPARISON_ID = f'{TEST_FW.uid};{TEST_FW_2.uid}'


class DbMock(CommonDatabaseMock):

    @staticmethod
    def comparison_exists(comparison_id):
        if comparison_id == COMPARISON_ID:
            return False
        return False

    @staticmethod
    def get_comparison_result(comparison_id):
        if comparison_id == COMPARISON_ID:
            return {
                'general': {'hid': {TEST_FW.uid: 'hid1', TEST_FW_2.uid: 'hid2'}},
                '_id': comparison_id,
                'submission_date': 0.0
            }
        return None


class ComparisonIntercomMock(CommonIntercomMock):

    def add_compare_task(self, compare_id, force=False):
        self.tasks.append((compare_id, force))


class TestAppCompare(WebInterfaceTest):

    def setup(self, *_, **__):
        super().setup(db_mock=DbMock, intercom_mock=ComparisonIntercomMock)

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
            rv = self.test_client.get('/comparison/add/{}'.format(TEST_FW.uid), follow_redirects=True)
            assert 'Remove All' in rv.data.decode()

    def test_start_compare(self):
        with self.test_client as tc:
            with tc.session_transaction() as test_session:
                test_session['uids_for_comparison'] = {TEST_FW.uid: None, TEST_FW_2.uid: None}
            rv = self.test_client.get('/compare', follow_redirects=True)
            assert b'Your compare task is in progress' in rv.data
            assert len(self.intercom.tasks) == 1, 'task not added'
            assert self.intercom.tasks[0] == (COMPARISON_ID, None), 'task not correct'

    def test_start_compare__force(self):
        with self.test_client as tc:
            with tc.session_transaction() as test_session:
                test_session['uids_for_comparison'] = {TEST_FW.uid: None, TEST_FW_2.uid: None}
            rv = self.test_client.get('/compare?force_recompare=true', follow_redirects=True)
            assert b'Your compare task is in progress' in rv.data
            assert len(self.intercom.tasks) == 1, 'task not added'
            assert self.intercom.tasks[0] == (COMPARISON_ID, True), 'task not correct'

    def test_start_compare__list_empty(self):
        rv = self.test_client.get('/compare', follow_redirects=True)
        assert b'No UIDs found for comparison' in rv.data

    def test_show_compare_result(self):
        rv = self.test_client.get(f'/compare/{COMPARISON_ID}', follow_redirects=True)
        assert b'General information' in rv.data
