import logging

import pytest
from sqlalchemy.exc import SQLAlchemyError

from fact.web_interface.components import user_management_routes
from fact.web_interface.components.user_management_routes import UserManagementRoutes
from fact.web_interface.security.privileges import ROLES

roles = sorted(ROLES)


class RoleMock:
    def __init__(self, name):
        self.name = name


class UserMock:
    def __init__(self, name, password, user_roles=None):
        self.id = 0
        self.email = name
        self.password = password
        self.api_key = 'abc123'
        self.active = True
        self.roles = user_roles or [RoleMock('superuser')]


class UserDbInterfaceMock:
    @staticmethod
    def list_users():
        return [UserMock('user_1', 'foo'), UserMock('user_2', 'bar')]

    @staticmethod
    def user_exists(user_name):
        return user_name == 'test'

    def create_user(self, email, password):
        pass

    def delete_user(self, user=None):
        pass

    @staticmethod
    def find_user(id=None, email=None):  # noqa: A002
        if id == '0':
            return UserMock('test_user', 'foo', user_roles=[RoleMock(roles[0]), RoleMock(roles[1])])
        if email == 'error':
            raise SQLAlchemyError('test')
        return None

    def password_is_correct(self, name, password):
        return password == 'correct password'

    def change_password(self, name, new_password):
        pass

    def role_exists(self, role):
        return False

    def create_role(self, name):
        pass

    def add_role_to_user(self, user=None, role=None):
        pass

    def remove_role_from_user(self, user=None, role=None):
        pass


@pytest.fixture
def current_user_fixture(monkeypatch):  # noqa: PT004
    monkeypatch.setattr(user_management_routes, 'current_user', UserMock('foobar', 'test'))


@pytest.mark.WebInterfaceUnitTestConfig(database_mock_class=UserDbInterfaceMock)
class TestAppUpload:
    def test_app_manage_users(self, test_client):
        response = test_client.get('/admin/manage_users', follow_redirects=True)
        assert b'user_1' in response.data
        assert b'user_2' in response.data

    def test_add_user(self, test_client):
        response = test_client.post(
            '/admin/manage_users',
            follow_redirects=True,
            data={'username': 'foobar', 'password1': 'test', 'password2': 'test'},
        )
        assert b'Successfully created user' in response.data

    def test_add_user__user_already_in_db(self, test_client):
        response = test_client.post(
            '/admin/manage_users',
            follow_redirects=True,
            data={'username': 'test', 'password1': 'test', 'password2': 'test'},
        )
        assert b'Error: user is already in the database' in response.data

    def test_add_user__no_match(self, test_client):
        response = test_client.post(
            '/admin/manage_users',
            follow_redirects=True,
            data={'username': 'foobar', 'password1': 'a', 'password2': 'b'},
        )
        assert b'Error: passwords do not match' in response.data

    def test_app_edit_user(self, test_client):
        response = test_client.get('/admin/user/0', follow_redirects=True)
        assert b'test_user' in response.data
        assert b'abc123' in response.data
        assert b'superuser' in response.data

    def test_app_edit_user__not_found(self, test_client):
        response = test_client.get('/admin/user/9999', follow_redirects=True)
        assert b'Error: user with ID 9999 not found' in response.data

    def test_app_delete_user(self, test_client):
        response = test_client.get('/admin/delete_user/test', follow_redirects=True)
        assert b'Successfully deleted user' in response.data

    def test_app_delete_user__error(self, test_client):
        response = test_client.get('/admin/delete_user/error', follow_redirects=True)
        assert b'Error: could not delete user' in response.data

    def test_change_user_password(self, test_client):
        response = test_client.post(
            '/admin/user/0',
            follow_redirects=True,
            data={'admin_change_password': 'test', 'admin_confirm_password': 'test'},
        )
        assert b'password change successful' in response.data

    def test_change_password__no_match(self, test_client):
        response = test_client.post(
            '/admin/user/0',
            follow_redirects=True,
            data={'admin_change_password': 'foo', 'admin_confirm_password': 'bar'},
        )
        assert b'Error: passwords do not match' in response.data

    def test_illegal_password(self, test_client):
        response = test_client.post(
            '/admin/user/0',
            follow_redirects=True,
            data={'admin_change_password': '1234567890abc', 'admin_confirm_password': '1234567890abc'},
        )
        assert b'password is not legal' in response.data

    @pytest.mark.usefixtures('current_user_fixture')
    def test_app_show_profile(self, test_client):
        response = test_client.get('/user_profile', follow_redirects=True)
        assert b'foobar' in response.data
        assert b'abc123' in response.data
        assert b'superuser' not in response.data

    @pytest.mark.usefixtures('current_user_fixture')
    def test_change_own_password(self, test_client):
        response = test_client.post(
            '/user_profile',
            follow_redirects=True,
            data={'new_password': 'foo', 'new_password_confirm': 'foo', 'old_password': 'correct password'},
        )
        assert b'password change successful' in response.data

    @pytest.mark.usefixtures('current_user_fixture')
    def test_wrong_password(self, test_client):
        response = test_client.post(
            '/user_profile',
            follow_redirects=True,
            data={'new_password': 'foo', 'new_password_confirm': 'foo', 'old_password': 'wrong password'},
        )
        assert b'Error: wrong password' in response.data

    @pytest.mark.usefixtures('current_user_fixture')
    def test_change_own_pw_illegal(self, test_client):
        response = test_client.post(
            '/user_profile',
            follow_redirects=True,
            data={
                'new_password': '1234567890abc',
                'new_password_confirm': '1234567890abc',
                'old_password': 'correct password',
            },
        )
        assert b'password is not legal' in response.data

    @pytest.mark.usefixtures('current_user_fixture')
    def test_change_own_pw_no_match(self, test_client):
        response = test_client.post(
            '/user_profile',
            follow_redirects=True,
            data={'new_password': 'foo', 'new_password_confirm': 'bar', 'old_password': 'correct password'},
        )
        assert b'Error: new password did not match' in response.data

    def test_edit_roles(self, test_client, caplog):
        # user 0 should have roles 0 and 1
        # this request should change the roles to 0 and 2 (add 2 and remove 1)
        with caplog.at_level(logging.INFO):
            test_client.post('/admin/user/0', follow_redirects=True, data={'input_roles': [roles[0], roles[2]]})
            assert 'Creating user role' in caplog.messages[0]
            assert f"added roles {{'{roles[2]}'}}, removed roles {{'{roles[1]}'}}" in caplog.messages[1]

    def test_edit_roles__error(self, test_client):
        response = test_client.post('/admin/user/0', follow_redirects=True, data={})
        assert b'unknown request' in response.data

    def test_edit_roles__unknown_element(self, test_client):
        response = test_client.post('/admin/user/9999', follow_redirects=True, data={'input_roles': [roles[0]]})
        assert b'user with ID 9999 not found' in response.data


@pytest.mark.parametrize(
    ('user_roles', 'role_indexes', 'expected_added_roles', 'expected_removed_roles'),
    [
        ([RoleMock(roles[0]), RoleMock(roles[1])], {roles[1], roles[2]}, {roles[2]}, {roles[0]}),
        ([RoleMock(roles[1])], {roles[1]}, set(), set()),
        ([RoleMock(r) for r in roles], set(), set(), set(roles)),
        ([], set(roles), set(roles), set()),
    ],
)
def test_determine_role_changes(user_roles, role_indexes, expected_added_roles, expected_removed_roles):
    added_roles, removed_roles = UserManagementRoutes._determine_role_changes(user_roles, role_indexes)
    assert added_roles == expected_added_roles
    assert removed_roles == expected_removed_roles
