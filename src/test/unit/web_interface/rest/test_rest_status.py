def test_empty_uid(test_app):
    result = test_app.get('/rest/status').json

    assert result['status'] == 0
    assert result['system_status'] == {
        'backend': {
            'system': {'cpu_percentage': 13.37},
            'analysis': {'current_analyses': [None, None]}
        },
        'database': None,
        'frontend': None
    }
