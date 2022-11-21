# pylint: disable=wrong-import-order
from flask import session

from test.common_helper import TEST_FW, TEST_FW_2
from test.unit.web_interface.base import WebInterfaceTest
from web_interface.components.compare_routes import CompareRoutes, get_comparison_uid_dict_from_session


class TestAppComparisonBasket(WebInterfaceTest):
    def test_get_comparison_uid_list_dict_session(self):
        with self.frontend.app.test_request_context():
            assert 'uids_for_comparison' not in session

            compare_list = get_comparison_uid_dict_from_session()
            assert 'uids_for_comparison' in session
            assert isinstance(session['uids_for_comparison'], dict)
            assert isinstance(compare_list, dict)

    def test_add_to_compare_basket(self):
        with self.frontend.app.test_request_context():
            assert 'uids_for_comparison' not in session

            CompareRoutes.add_to_compare_basket(self.frontend, 'test')
            assert 'uids_for_comparison' in session
            assert isinstance(session['uids_for_comparison'], dict)
            assert 'test' in session['uids_for_comparison']

    def test_remove_from_compare_basket(self):
        with self.frontend.app.test_request_context():
            CompareRoutes.add_to_compare_basket(self.frontend, TEST_FW.uid)
            CompareRoutes.add_to_compare_basket(self.frontend, TEST_FW_2.uid)
            assert 'uids_for_comparison' in session
            assert TEST_FW.uid in session['uids_for_comparison']
            assert TEST_FW_2.uid in session['uids_for_comparison']

            CompareRoutes.remove_from_compare_basket(self.frontend, 'some_uid', TEST_FW.uid)
            assert TEST_FW.uid not in session['uids_for_comparison']
            assert TEST_FW_2.uid in session['uids_for_comparison']

    def test_remove_all_from_compare_basket(self):
        with self.frontend.app.test_request_context():
            session['uids_for_comparison'] = [TEST_FW.uid, TEST_FW_2.uid]
            session.modified = True  # pylint: disable=assigning-non-slot
            assert 'uids_for_comparison' in session
            assert TEST_FW.uid in session['uids_for_comparison']
            assert TEST_FW_2.uid in session['uids_for_comparison']

            CompareRoutes.remove_all_from_compare_basket(self.frontend, 'some_uid')
            assert TEST_FW.uid not in session['uids_for_comparison']
            assert TEST_FW_2.uid not in session['uids_for_comparison']
