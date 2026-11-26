import re

from storage.db_interface_frontend import CachedQuery
from test.common_helper import create_test_file_object

RULE_UID = 'decd4f7805e81c4730fc97cc65e10c53519dbbc65730e477685ee05ad105e319_10'

COMMENT1 = {'id': 'id1', 'author': 'foo', 'comment': 'bar', 'time': '123', 'plugin': 'plugin1'}
COMMENT2 = {'id': 'id2', 'author': 'foo', 'comment': 'bar', 'time': '456', 'plugin': ''}
COMMENT3 = {'id': 'id3', 'author': 'foo', 'comment': 'bar', 'time': '456', 'plugin': 'plugin2'}


def test_add_comment_to_object(backend_db, frontend_editing_db, frontend_db):
    fo = create_test_file_object()
    fo.comments = [COMMENT1]
    backend_db.insert_object(fo)

    new_comment = frontend_editing_db.add_comment_to_object(
        fo.uid, COMMENT2['comment'], COMMENT2['author'], int(COMMENT2['time']), COMMENT2['plugin']
    )

    assert re.fullmatch(r'[0-9a-f]{32}', new_comment['id'])
    assert new_comment == {**COMMENT2, 'id': new_comment['id']}
    fo_from_db = frontend_db.get_object(fo.uid)
    assert fo_from_db.comments == [COMMENT1, new_comment]


def test_delete_comment(backend_db, frontend_editing_db, frontend_db):
    fo = create_test_file_object()
    fo.comments = [COMMENT1, COMMENT2, COMMENT3]
    backend_db.insert_object(fo)

    frontend_editing_db.delete_comment(fo.uid, comment_id=COMMENT2['id'])

    fo_from_db = frontend_db.get_object(fo.uid)
    assert fo_from_db.comments == [COMMENT1, COMMENT3], 'COMMENT3 has the same time but should not be deleted'


def test_search_cache_insert(frontend_editing_db, frontend_db):
    result = frontend_db.get_query_from_cache(RULE_UID)
    assert result is None

    match_data = {'some_uid': {'foo': []}}
    result = frontend_editing_db.add_to_search_query_cache('{"foo": "bar"}', match_data, 'rule foo{}')
    assert result == RULE_UID

    result = frontend_db.get_query_from_cache(RULE_UID)
    assert isinstance(result, CachedQuery)
    assert result.query == '{"foo": "bar"}'
    assert result.yara_rule == 'rule foo{}'
    assert result.match_data == match_data


def test_search_cache_update(frontend_editing_db, frontend_db):
    assert frontend_editing_db.add_to_search_query_cache('{"uid": "some uid"}', {}, 'rule foo{}') == RULE_UID
    # update
    assert frontend_editing_db.add_to_search_query_cache('{"uid": "some other uid"}', {}, 'rule foo{}') == RULE_UID

    assert frontend_db.get_query_from_cache(RULE_UID).query == '{"uid": "some other uid"}'
