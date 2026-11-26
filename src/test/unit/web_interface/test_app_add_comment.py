import pytest

from test.common_helper import AUTHENTICATION_CONFIG, TEST_FW, TEST_SUPERUSER_API_KEY, CommonDatabaseMock


class DbMock(CommonDatabaseMock):
    @staticmethod
    def add_comment_to_object(_, comment, author, time, plugin):
        TEST_FW.comments.append({'time': str(time), 'author': author, 'comment': comment, 'plugin': plugin})


@pytest.fixture(autouse=True)
def _restore_comments():
    comments = list(TEST_FW.comments)
    yield
    TEST_FW.comments = comments


def _post_comment(test_client, author: str, headers: dict | None = None):
    data = {'comment': 'this is the test comment', 'author': author, 'plugin': ''}
    return test_client.post(
        f'/comment/{TEST_FW.uid}',
        content_type='multipart/form-data',
        data=data,
        headers=headers or {},
        follow_redirects=True,
    )


@pytest.mark.WebInterfaceUnitTestConfig(database_mock_class=DbMock)
class TestAppAddComment:
    def test_app_add_comment_put(self, test_client):
        rv = _post_comment(test_client, 'test author')

        assert b'Analysis' in rv.data
        assert b'this is the test comment' in rv.data
        assert TEST_FW.comments[-1]['author'] == 'test author'

    def test_empty_author_is_anonymous(self, test_client):
        _post_comment(test_client, ' ')

        assert TEST_FW.comments[-1]['author'] == 'anonymous'

    @pytest.mark.frontend_config_overwrite(AUTHENTICATION_CONFIG)
    def test_author_is_the_logged_in_user(self, test_client):
        _post_comment(test_client, 'someone else', headers={'Authorization': TEST_SUPERUSER_API_KEY})

        assert TEST_FW.comments[-1]['author'] == 't_superuser'

    @pytest.mark.frontend_config_overwrite(AUTHENTICATION_CONFIG)
    def test_form_has_no_author_field_with_authentication(self, test_client):
        rv = test_client.get(f'/analysis/{TEST_FW.uid}', headers={'Authorization': TEST_SUPERUSER_API_KEY})

        assert b'id="addCommentForm"' in rv.data
        assert b'name="author"' not in rv.data  # nothing to send: FACT sets the author
        assert b'id="author" value="t_superuser" readonly' in rv.data

    def test_form_has_author_field_without_authentication(self, test_client):
        rv = test_client.get(f'/analysis/{TEST_FW.uid}')

        assert b'name="author"' in rv.data
