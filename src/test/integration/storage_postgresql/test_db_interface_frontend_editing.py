from test.common_helper import create_test_file_object

COMMENT1 = {'author': 'foo', 'comment': 'bar', 'time': '123'}
COMMENT2 = {'author': 'foo', 'comment': 'bar', 'time': '456'}
COMMENT3 = {'author': 'foo', 'comment': 'bar', 'time': '789'}


def test_add_comment_to_object(db):
    fo = create_test_file_object()
    fo.comments = [COMMENT1]
    db.backend.insert_object(fo)

    db.frontend_ed.add_comment_to_object(fo.uid, COMMENT2['comment'], COMMENT2['author'], int(COMMENT2['time']))

    fo_from_db = db.frontend.get_object(fo.uid)
    assert fo_from_db.comments == [COMMENT1, COMMENT2]


def test_delete_comment(db):
    fo = create_test_file_object()
    fo.comments = [COMMENT1, COMMENT2, COMMENT3]
    db.backend.insert_object(fo)

    db.frontend_ed.delete_comment(fo.uid, timestamp=COMMENT2['time'])

    fo_from_db = db.frontend.get_object(fo.uid)
    assert COMMENT2 not in fo_from_db.comments
    assert fo_from_db.comments == [COMMENT1, COMMENT3]


def test_search_cache(db):
    uid = '426fc04f04bf8fdb5831dc37bbb6dcf70f63a37e05a68c6ea5f63e85ae579376_14'
    result = db.frontend.get_query_from_cache(uid)
    assert result is None

    result = db.frontend_ed.add_to_search_query_cache('{"foo": "bar"}', 'foo')
    assert result == uid

    result = db.frontend.get_query_from_cache(uid)
    assert isinstance(result, dict)
    assert result['search_query'] == '{"foo": "bar"}'
    assert result['query_title'] == 'foo'
