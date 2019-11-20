import unittest
import unittest.mock

import pytest
from sqlalchemy.exc import SQLAlchemyError

from test.common_helper import get_config_for_testing
from web_interface import frontend_main
from web_interface.components import user_management_routes
from web_interface.components.user_management_routes import UserManagementRoutes
from web_interface.security.authentication import add_flask_security_to_app
from web_interface.security.privileges import ROLES

roles = sorted(ROLES)


class RoleMock:
    def __init__(self, name):
        self.name = name


class UserMock:
    def __init__(self, name, password):
        self.id = 0
        self.email = name
        self.password = password
        self.api_key = 'abc123'
        self.active = True
        self.roles = [RoleMock('superuser')]


class UserDbMock:
    class session:
        @staticmethod
        def commit():
            pass

        @staticmethod
        def rollback():
            pass


class UserDbInterfaceMock:
    @staticmethod
    def list_users():
        return [
            UserMock('user_1', 'foo'),
            UserMock('user_2', 'bar')
        ]

    @staticmethod
    def user_exists(user_name):
        return user_name == 'test'

    def create_user(self, email, password):
        pass

    def delete_user(self, user=None):
        pass

    @staticmethod
    def find_user(id=None, email=None):
        if id == '0' or email == 'test_user':
            return UserMock('test_user', 'foo')
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


def add_security_get_mocked(app, config):
    add_flask_security_to_app(app, config)
    return UserDbMock(), UserDbInterfaceMock()


@pytest.fixture
def current_user_fixture(monkeypatch):
    monkeypatch.setattr(user_management_routes, 'current_user', UserMock('foobar', 'test'))


class UserManagementRoutesTest(unittest.TestCase):

    def setUp(self):
        self.config = get_config_for_testing()

        self.enter_patch = unittest.mock.patch(target='web_interface.frontend_main.add_flask_security_to_app', new=add_security_get_mocked)
        self.enter_patch.start()

        self.frontend = frontend_main.WebFrontEnd(config=self.config)

        self.frontend.app.config['TESTING'] = True
        self.test_client = self.frontend.app.test_client()

    def tearDown(self):
        self.enter_patch.stop()

    def test_app_manage_users(self):
        response = self.test_client.get('/admin/manage_users', follow_redirects=True)
        assert b'user_1' in response.data
        assert b'user_2' in response.data

    def test_add_user(self):
        response = self.test_client.post('/admin/manage_users', follow_redirects=True, data={
            'username': 'foobar',
            'password1': 'test',
            'password2': 'test'
        })
        assert b'Successfully created user' in response.data

    def test_add_user__user_already_in_db(self):
        response = self.test_client.post('/admin/manage_users', follow_redirects=True, data={
            'username': 'test',
            'password1': 'test',
            'password2': 'test'
        })
        assert b'Error: user is already in the database' in response.data

    def test_add_user__passwords_do_not_match(self):
        response = self.test_client.post('/admin/manage_users', follow_redirects=True, data={
            'username': 'foobar',
            'password1': 'a',
            'password2': 'b'
        })
        assert b'Error: passwords do not match' in response.data

    def test_app_edit_user(self):
        response = self.test_client.get('/admin/user/0', follow_redirects=True)
        assert b'test_user' in response.data
        assert b'abc123' in response.data
        assert b'superuser' in response.data

    def test_app_edit_user__not_found(self):
        response = self.test_client.get('/admin/user/9999', follow_redirects=True)
        assert b'Error: user with ID 9999 not found' in response.data

    def test_app_delete_user(self):
        response = self.test_client.get('/admin/delete_user/test', follow_redirects=True)
        assert b'Successfully deleted user' in response.data

    def test_app_delete_user__error(self):
        response = self.test_client.get('/admin/delete_user/error', follow_redirects=True)
        assert b'Error: could not delete user' in response.data

    def test_change_user_password(self):
        response = self.test_client.post('/admin/user/0', follow_redirects=True, data={
            'admin_change_password': 'test',
            'admin_confirm_password': 'test'
        })
        assert b'password change successful' in response.data

    def test_change_user_password__passwords_do_not_match(self):
        response = self.test_client.post('/admin/user/0', follow_redirects=True, data={
            'admin_change_password': 'foo',
            'admin_confirm_password': 'bar'
        })
        assert b'Error: passwords do not match' in response.data

    def test_change_user_password__illegal_password(self):
        response = self.test_client.post('/admin/user/0', follow_redirects=True, data={
            'admin_change_password': '1234567890abc',
            'admin_confirm_password': '1234567890abc'
        })
        assert b'password is not legal' in response.data

    @pytest.mark.usefixtures('current_user_fixture')
    def test_app_show_profile(self):
        response = self.test_client.get('/user_profile', follow_redirects=True)
        assert b'foobar' in response.data
        assert b'abc123' in response.data
        assert b'superuser' not in response.data

    @pytest.mark.usefixtures('current_user_fixture')
    def test_change_own_password(self):
        response = self.test_client.post('/user_profile', follow_redirects=True, data={
            'new_password': 'foo',
            'new_password_confirm': 'foo',
            'old_password': 'correct password'
        })
        assert b'password change successful' in response.data

    @pytest.mark.usefixtures('current_user_fixture')
    def test_change_own_password__wrong_password(self):
        response = self.test_client.post('/user_profile', follow_redirects=True, data={
            'new_password': 'foo',
            'new_password_confirm': 'foo',
            'old_password': 'wrong password'
        })
        assert b'Error: wrong password' in response.data

    @pytest.mark.usefixtures('current_user_fixture')
    def test_change_own_password__illegal_password(self):
        response = self.test_client.post('/user_profile', follow_redirects=True, data={
            'new_password': '1234567890abc',
            'new_password_confirm': '1234567890abc',
            'old_password': 'correct password'
        })
        assert b'password is not legal' in response.data

    @pytest.mark.usefixtures('current_user_fixture')
    def test_change_own_password__passwords_do_not_match(self):
        response = self.test_client.post('/user_profile', follow_redirects=True, data={
            'new_password': 'foo',
            'new_password_confirm': 'bar',
            'old_password': 'correct password'
        })
        assert b'Error: new password did not match' in response.data

    def test_edit_roles(self):
        response = self.test_client.post('/admin/edit_user', follow_redirects=True, data={
            'name': 'roles',
            'pk': 'test_user',
            'value[]': ['0']
        })
        assert response.data == b'OK'

    def test_edit_roles__error(self):
        response = self.test_client.post('/admin/edit_user', follow_redirects=True, data={
            'name': 'roles',
            'pk': 'error',
            'value[]': ['0']
        })
        assert response.data == b'Not found'

    def test_edit_roles__unknown_element(self):
        response = self.test_client.post('/admin/edit_user', follow_redirects=True, data={
            'name': 'unknown element',
            'pk': 'test_user',
            'value[]': ['0']
        })
        assert response.data == b'Not found'


@pytest.mark.parametrize('user_roles, role_indexes, expected_added_roles, expected_removed_roles', [
    ([RoleMock(roles[-1])], ['0'], [roles[0]], [roles[-1]]),
    ([RoleMock(roles[0])], ['0'], [], []),
    ([RoleMock(r) for r in roles], [], [], roles),
    ([], [str(i) for i in range(len(roles))], roles, []),
])
def test_determine_role_changes(user_roles, role_indexes, expected_added_roles, expected_removed_roles):
    added_roles, removed_roles = UserManagementRoutes._determine_role_changes(user_roles, role_indexes)
    assert added_roles == expected_added_roles
    assert removed_roles == expected_removed_roles
