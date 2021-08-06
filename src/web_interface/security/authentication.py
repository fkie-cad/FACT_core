import base64
import os

from flask_security import AnonymousUser, RoleMixin, Security, UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.local import LocalProxy

from web_interface.security.privileges import PRIVILEGES
from web_interface.security.user_role_db_interface import UserRoleDbInterface


def add_flask_security_to_app(app, config):
    _add_configuration_to_app(app, config)

    db = SQLAlchemy(app)

    user_interface = create_user_interface(db)
    security = Security(app, user_interface)

    _add_apikey_handler(security, user_interface)
    return db, user_interface


def create_user_interface(db):
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
        # See flask_security.models.fsqla.FsUserMixin
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


def _add_configuration_to_app(app, config):
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECURITY_PASSWORD_SALT'] = config.get('data_storage', 'password_salt').encode()
    app.config['SQLALCHEMY_DATABASE_URI'] = config.get('data_storage', 'user_database', fallback='sqlite:///')
    app.config['SECURITY_UNAUTHORIZED_VIEW'] = '/login'
    app.config['LOGIN_DISABLED'] = not config.getboolean('ExpertSettings', 'authentication')


def _build_api_key():
    raw_key = os.urandom(32)
    return base64.standard_b64encode(raw_key).decode()


def _auth_is_disabled(user):
    user_object = user._get_current_object() if isinstance(user, LocalProxy) else user
    return isinstance(user_object, AnonymousUser)


def user_has_privilege(user, privilege='delete'):
    return _auth_is_disabled(user) or any(user.has_role(role) for role in PRIVILEGES[privilege])
