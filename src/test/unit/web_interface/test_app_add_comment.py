from test.common_helper import TEST_FW
from test.unit.web_interface.base import WebInterfaceTest


class TestAppAddComment(WebInterfaceTest):

    def test_app_add_comment_get_not_in_db(self):
        rv = self.test_client.get('/comment/abc_123')
        assert b'Error: UID not found in database' in rv.data

    def test_app_add_comment_get_valid_uid(self):
        rv = self.test_client.get('/comment/{}'.format(TEST_FW.uid))
        assert b'Error: UID not found in database' not in rv.data
        assert b'Add Comment' in rv.data

    def test_app_add_comment_put(self):
        rv = self.test_client.post('/comment/{}'.format(TEST_FW.uid), content_type='multipart/form-data', data={
            'comment': "this is the test comment",
            'author': "test author"}, follow_redirects=True)
        assert b'Analysis' in rv.data
        assert b'this is the test comment' in rv.data
