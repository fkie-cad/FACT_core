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


class StatisticDbViewerMock:
    @staticmethod
    def get_statistic(_):
        return {}  # status not (yet?) in DB

    @staticmethod
    def get_available_analysis_plugins():
        return []


def test_empty_result(test_app, monkeypatch):
    monkeypatch.setattr('helperFunctions.database.ConnectTo.__enter__', lambda _: StatisticDbViewerMock())
    result = test_app.get('/rest/status').json
    assert 'Cannot get FACT component status' in result['error_message']
