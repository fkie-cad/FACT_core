import pytest
from flask import Flask
from flask_security import Security
from flask_sqlalchemy import SQLAlchemy

from web_interface.security.authentication import create_user_datastore


@pytest.fixture
def app_database_tuple():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECURITY_PASSWORD_SALT'] = 'salt123'
    app.config['SECRET_KEY'] = 'key123'

    db = SQLAlchemy(app)
    db_interface = create_user_datastore(db)
    Security(app, db_interface)
    db.create_all()

    yield app, db_interface


@pytest.fixture
def test_app(app_database_tuple):
    app, _ = app_database_tuple
    yield app


@pytest.fixture
def test_db_interface(app_database_tuple):
    _, db_interface = app_database_tuple
    yield db_interface


def test_add_and_find_user(test_app, test_db_interface):
    with test_app.app_context():
        user_name, password = ('test_user', 'password')
        test_db_interface.create_user(email=user_name, password=password)
        user = test_db_interface.find_user(email=user_name)
        assert user.email == user_name
        assert test_db_interface.password_is_correct(user_name, password)


def test_list_users(test_app, test_db_interface):
    test_users = ['test_user_1', 'test_user_2', 'test_user_3']
    for user in test_users:
        test_db_interface.create_user(email=user, password='foobar')

    user_list = test_db_interface.list_users()
    assert len(user_list) == 3
    assert all(user in [u.email for u in user_list] for user in test_users)


def test_change_password(test_app, test_db_interface):
    with test_app.app_context():
        user_name, password, new_password = 'test_user', 'password', 'new_password'
        test_db_interface.create_user(email=user_name, password=password)
        assert test_db_interface.password_is_correct(user_name, password)

        test_db_interface.change_password(user_name, new_password)
        assert test_db_interface.password_is_correct(user_name, new_password)


def test_user_exists(test_app, test_db_interface):
    with test_app.app_context():
        assert test_db_interface.user_exists('test_user') is False

        user_name, password, _ = 'test_user', 'password', 'new_password'
        test_db_interface.create_user(email=user_name, password=password)
        assert test_db_interface.user_exists('test_user') is True


def test_role_exists(test_app, test_db_interface):
    with test_app.app_context():
        assert test_db_interface.role_exists('test_role') is False
        test_db_interface.create_role(name='test_role')
        assert test_db_interface.role_exists('test_role') is True
