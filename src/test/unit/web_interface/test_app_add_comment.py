from test.common_helper import TEST_FW, CommonDatabaseMock
from test.unit.web_interface.base import WebInterfaceTest


class DbMock(CommonDatabaseMock):
    @staticmethod
    def add_comment_to_object(_, comment, author, time):
        TEST_FW.comments.append({'time': str(time), 'author': author, 'comment': comment})


class TestAppAddComment(WebInterfaceTest):
    @classmethod
    def setup_class(cls, *_, **__):
        super().setup_class(db_mock=DbMock)

    def test_app_add_comment_get_not_in_db(self):
        rv = self.test_client.get('/comment/abc_123')
        assert b'Error: UID not found in database' in rv.data

    def test_app_add_comment_get_valid_uid(self):
        rv = self.test_client.get(f'/comment/{TEST_FW.uid}')
        assert b'Error: UID not found in database' not in rv.data
        assert b'Add Comment' in rv.data

    def test_app_add_comment_put(self):
        data = {'comment': 'this is the test comment', 'author': 'test author'}
        rv = self.test_client.post(
            f'/comment/{TEST_FW.uid}',
            content_type='multipart/form-data',
            data=data,
            follow_redirects=True,
        )
        assert b'Analysis' in rv.data
        assert b'this is the test comment' in rv.data
