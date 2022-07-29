# pylint: disable=no-self-use
import pytest

from test.common_helper import TEST_FW, CommonDatabaseMock


class DbMock(CommonDatabaseMock):

    @staticmethod
    def add_comment_to_object(_, comment, author, time):
        TEST_FW.comments.append(
            {'time': str(time), 'author': author, 'comment': comment}
        )


@pytest.mark.DatabaseMockClass(lambda: DbMock)
class TestAppAddComment:
    def test_app_add_comment_get_not_in_db(self, test_client):
        rv = test_client.get('/comment/abc_123')
        assert b'Error: UID not found in database' in rv.data

    def test_app_add_comment_get_valid_uid(self, test_client):
        rv = test_client.get(f'/comment/{TEST_FW.uid}')
        assert b'Error: UID not found in database' not in rv.data
        assert b'Add Comment' in rv.data

    def test_app_add_comment_put(self, test_client):
        data = {'comment': 'this is the test comment', 'author': 'test author'}
        rv = test_client.post(f'/comment/{TEST_FW.uid}', content_type='multipart/form-data', data=data, follow_redirects=True)
        assert b'Analysis' in rv.data
        assert b'this is the test comment' in rv.data
