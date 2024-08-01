from fact.storage.db_interface_frontend import CachedQuery
from fact.test.common_helper import create_test_file_object

RULE_UID = 'decd4f7805e81c4730fc97cc65e10c53519dbbc65730e477685ee05ad105e319_10'

COMMENT1 = {'author': 'foo', 'comment': 'bar', 'time': '123'}
COMMENT2 = {'author': 'foo', 'comment': 'bar', 'time': '456'}
COMMENT3 = {'author': 'foo', 'comment': 'bar', 'time': '789'}


def test_add_comment_to_object(backend_db, frontend_editing_db, frontend_db):
    fo = create_test_file_object()
    fo.comments = [COMMENT1]
    backend_db.insert_object(fo)

    frontend_editing_db.add_comment_to_object(fo.uid, COMMENT2['comment'], COMMENT2['author'], int(COMMENT2['time']))

    fo_from_db = frontend_db.get_object(fo.uid)
    assert fo_from_db.comments == [COMMENT1, COMMENT2]


def test_delete_comment(backend_db, frontend_editing_db, frontend_db):
    fo = create_test_file_object()
    fo.comments = [COMMENT1, COMMENT2, COMMENT3]
    backend_db.insert_object(fo)

    frontend_editing_db.delete_comment(fo.uid, timestamp=COMMENT2['time'])

    fo_from_db = frontend_db.get_object(fo.uid)
    assert COMMENT2 not in fo_from_db.comments
    assert fo_from_db.comments == [COMMENT1, COMMENT3]


def test_search_cache_insert(frontend_editing_db, frontend_db):
    result = frontend_db.get_query_from_cache(RULE_UID)
    assert result is None

    result = frontend_editing_db.add_to_search_query_cache('{"foo": "bar"}', 'rule foo{}')
    assert result == RULE_UID

    result = frontend_db.get_query_from_cache(RULE_UID)
    assert isinstance(result, CachedQuery)
    assert result.query == '{"foo": "bar"}'
    assert result.yara_rule == 'rule foo{}'


def test_search_cache_update(frontend_editing_db, frontend_db):
    assert frontend_editing_db.add_to_search_query_cache('{"uid": "some uid"}', 'rule foo{}') == RULE_UID
    # update
    assert frontend_editing_db.add_to_search_query_cache('{"uid": "some other uid"}', 'rule foo{}') == RULE_UID

    assert frontend_db.get_query_from_cache(RULE_UID).query == '{"uid": "some other uid"}'
