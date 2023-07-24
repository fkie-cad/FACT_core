import pytest

from test.common_helper import TEST_FW, CommonDatabaseMock


def test_app_download_raw_invalid(test_client):
    rv = test_client.get('/download/invalid_uid')
    assert b'File not found in database: invalid_uid' in rv.data


def test_app_download_raw_error(test_client):
    rv = test_client.get('/download/error')
    assert b'<strong>Error!</strong>  timeout' in rv.data


class DbMock(CommonDatabaseMock):
    def get_analysis(self, uid, plugin):
        return {'mime': 'application/x-foobar'}


@pytest.mark.WebInterfaceUnitTestConfig(database_mock_class=DbMock)
def test_app_download_raw(test_client):
    rv = test_client.get(f'/download/{TEST_FW.uid}')
    assert TEST_FW.binary in rv.data
    assert 'attachment; filename=test.zip' in rv.headers['Content-Disposition']
    assert rv.headers['Content-Type'] == 'application/x-foobar'


@pytest.mark.WebInterfaceUnitTestConfig(database_mock_class=DbMock)
def test_app_download_missing_mime(test_client, monkeypatch):
    monkeypatch.setattr(DbMock, 'get_analysis', lambda *_: None)  # simulate missing file type analysis
    rv = test_client.get(f'/download/{TEST_FW.uid}')
    assert TEST_FW.binary in rv.data
    assert rv.headers['Content-Type'] == 'application/zip', 'MIME data should be generated if the DB entry is missing'


def test_app_tar_download(test_client):
    rv = test_client.get(f'/tar-download/{TEST_FW.uid}')
    assert TEST_FW.binary in rv.data
    assert 'attachment; filename=test.zip' in rv.headers['Content-Disposition']
    assert rv.headers['Content-Type'] == 'application/gzip'
