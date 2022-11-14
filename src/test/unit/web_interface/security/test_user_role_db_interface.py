from unittest import TestCase

from flask import Flask
from flask_security import Security
from flask_sqlalchemy import SQLAlchemy

from web_interface.security.authentication import create_user_datastore


class TestUserRoleDbInterface(TestCase):
    def setUp(self):
        self.test_app = Flask(__name__)
        self.test_app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///'
        self.test_app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        self.test_app.config['SECURITY_PASSWORD_SALT'] = 'salt123'
        self.test_app.config['SECRET_KEY'] = 'key123'
        db = SQLAlchemy(self.test_app)
        self.db_interface = create_user_datastore(db)
        Security(self.test_app, self.db_interface)
        db.create_all()

    def test_add_and_find_user(self):
        with self.test_app.app_context():
            user_name, password = ('test_user', 'password')
            self.db_interface.create_user(email=user_name, password=password)
            user = self.db_interface.find_user(email=user_name)
            assert user.email == user_name
            assert self.db_interface.password_is_correct(user_name, password)

    def test_list_users(self):
        test_users = ['test_user_1', 'test_user_2', 'test_user_3']
        for user in test_users:
            self.db_interface.create_user(email=user, password='foobar')

        user_list = self.db_interface.list_users()
        assert len(user_list) == 3
        assert all(user in [u.email for u in user_list] for user in test_users)

    def test_change_password(self):
        with self.test_app.app_context():
            user_name, password, new_password = 'test_user', 'password', 'new_password'
            self.db_interface.create_user(email=user_name, password=password)
            assert self.db_interface.password_is_correct(user_name, password)

            self.db_interface.change_password(user_name, new_password)
            assert self.db_interface.password_is_correct(user_name, new_password)

    def test_user_exists(self):
        with self.test_app.app_context():
            assert self.db_interface.user_exists('test_user') is False

            user_name, password, _ = 'test_user', 'password', 'new_password'
            self.db_interface.create_user(email=user_name, password=password)
            assert self.db_interface.user_exists('test_user') is True

    def test_role_exists(self):
        with self.test_app.app_context():
            assert self.db_interface.role_exists('test_role') is False
            self.db_interface.create_role(name='test_role')
            assert self.db_interface.role_exists('test_role') is True
