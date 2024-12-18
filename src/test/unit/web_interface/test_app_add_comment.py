import pytest

from test.common_helper import TEST_FW, CommonDatabaseMock


class DbMock(CommonDatabaseMock):
    @staticmethod
    def add_comment_to_object(_, comment, author, time):
        TEST_FW.comments.append({'time': str(time), 'author': author, 'comment': comment})


@pytest.mark.WebInterfaceUnitTestConfig(database_mock_class=DbMock)
class TestAppAddComment:
    def test_app_add_comment_put(self, test_client):
        data = {'comment': 'this is the test comment', 'author': 'test author'}
        rv = test_client.post(
            f'/comment/{TEST_FW.uid}', content_type='multipart/form-data', data=data, follow_redirects=True
        )
        assert b'Analysis' in rv.data
        assert b'this is the test comment' in rv.data
