from flask import session

from test.common_helper import TEST_FW, TEST_FW_2
from web_interface.components.comparison_routes import ComparisonRoutes, get_comparison_uid_dict_from_session


def test_get_comparison_uid_list_dict_session(web_frontend):
    with web_frontend.app.test_request_context():
        assert 'uids_for_comparison' not in session

        comparison_list = get_comparison_uid_dict_from_session()
        assert 'uids_for_comparison' in session
        assert isinstance(session['uids_for_comparison'], dict)
        assert isinstance(comparison_list, dict)


def test_add_to_comparison_basket(web_frontend):
    with web_frontend.app.test_request_context():
        assert 'uids_for_comparison' not in session

        ComparisonRoutes.add_to_comparison_basket(web_frontend, 'test')
        assert 'uids_for_comparison' in session
        assert isinstance(session['uids_for_comparison'], dict)
        assert 'test' in session['uids_for_comparison']


def test_remove_from_comparison_basket(web_frontend):
    with web_frontend.app.test_request_context():
        ComparisonRoutes.add_to_comparison_basket(web_frontend, TEST_FW.uid)
        ComparisonRoutes.add_to_comparison_basket(web_frontend, TEST_FW_2.uid)
        assert 'uids_for_comparison' in session
        assert TEST_FW.uid in session['uids_for_comparison']
        assert TEST_FW_2.uid in session['uids_for_comparison']

        ComparisonRoutes.remove_from_comparison_basket(web_frontend, 'some_uid', TEST_FW.uid)
        assert TEST_FW.uid not in session['uids_for_comparison']
        assert TEST_FW_2.uid in session['uids_for_comparison']


def test_remove_all_from_comparison_basket(web_frontend):
    with web_frontend.app.test_request_context():
        session['uids_for_comparison'] = [TEST_FW.uid, TEST_FW_2.uid]
        session.modified = True
        assert 'uids_for_comparison' in session
        assert TEST_FW.uid in session['uids_for_comparison']
        assert TEST_FW_2.uid in session['uids_for_comparison']

        ComparisonRoutes.remove_all_from_comparison_basket(web_frontend, 'some_uid')
        assert TEST_FW.uid not in session['uids_for_comparison']
        assert TEST_FW_2.uid not in session['uids_for_comparison']
