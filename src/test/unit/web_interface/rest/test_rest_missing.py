def test_missing(test_app):
    result = test_app.get('/rest/missing').json

    assert 'missing_analyses' in result
    assert result['missing_analyses'] == {'root_fw_uid': ['missing_child_uid']}
    assert 'missing_files' in result
    assert result['missing_files'] == {'parent_uid': ['missing_child_uid']}
