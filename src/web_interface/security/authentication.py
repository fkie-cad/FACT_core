import base64
import os

from flask_security import AnonymousUser, LoginForm, RoleMixin, Security, UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.local import LocalProxy
from wtforms import StringField
from wtforms.validators import DataRequired

from web_interface.security.privileges import PRIVILEGES
from web_interface.security.user_role_db_interface import UserRoleDbInterface


def add_flask_security_to_app(app):
    db = SQLAlchemy(app)
    user_datastore = create_user_datastore(db)

    # Allow users to enter non-emails in the html form
    # See add_config_from_configparser_to_app for explanation why we need this
    class CustomLoginForm(LoginForm):
        email = StringField('username', [DataRequired()])

    security = Security(app, user_datastore, login_form=CustomLoginForm)

    _add_apikey_handler(security, user_datastore)
    return db, user_datastore


def create_user_datastore(db):
    # pylint: disable=no-member

    roles_users = db.Table('roles_users', db.Column('user_id', db.Integer(), db.ForeignKey('user.id')), db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))

    class Role(db.Model, RoleMixin):
        id = db.Column(db.Integer(), primary_key=True)  # pylint: disable=invalid-name
        name = db.Column(db.String(80), unique=True)
        description = db.Column(db.String(255))

    class User(db.Model, UserMixin):
        id = db.Column(db.Integer, primary_key=True)  # pylint: disable=invalid-name
        api_key = db.Column(db.String(255), default=_build_api_key, unique=True)
        email = db.Column(db.String(255), unique=True)
        password = db.Column(db.String(255))
        active = db.Column(db.Boolean())
        confirmed_at = db.Column(db.DateTime())
        roles = db.relationship('Role', secondary=roles_users, backref=db.backref('users', lazy='dynamic'))
        fs_uniquifier = db.Column(db.String(64), unique=True, nullable=False)

    return UserRoleDbInterface(db, User, Role)


def _add_apikey_handler(security, user_datastore):
    @security.login_manager.request_loader
    def load_user_from_request(request):  # pylint: disable=unused-variable
        api_key = request.headers.get('Authorization')
        if api_key:
            user = user_datastore.find_user(api_key=api_key)
            if user:
                return user
        return None


def _build_api_key():
    raw_key = os.urandom(32)
    return base64.standard_b64encode(raw_key).decode()


def _auth_is_disabled(user):
    user_object = user._get_current_object() if isinstance(user, LocalProxy) else user  # pylint: disable=protected-access
    return isinstance(user_object, AnonymousUser)


def user_has_privilege(user, privilege='delete'):
    return _auth_is_disabled(user) or any(user.has_role(role) for role in PRIVILEGES[privilege])
