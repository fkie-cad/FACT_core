import base64
import os

from flask_security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin
from flask_sqlalchemy import SQLAlchemy


def add_flask_security_to_app(app, config):
    _add_configuration_to_app(app, config)

    db = SQLAlchemy(app)

    user_datastore = create_db_interface(db)
    security = Security(app, user_datastore)

    _add_apikey_handler(security, user_datastore)


def _add_apikey_handler(security, user_datastore):
    @security.login_manager.request_loader
    def load_user_from_request(request):
        api_key = request.headers.get('Authorization')
        if api_key:
            user = user_datastore.find_user(api_key=api_key)
            if user:
                return user
        return None


def _add_configuration_to_app(app, config):
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECURITY_PASSWORD_SALT'] = b'SUPERH\x45H'
    app.config['SQLALCHEMY_DATABASE_URI'] = config.get('data_storage', 'user_database', fallback='sqlite:///')
    app.config['SECURITY_UNAUTHORIZED_VIEW'] = '/login'
    app.config['LOGIN_DISABLED'] = not config.getboolean('ExpertSettings', 'authentication')


def create_db_interface(db):
    roles_users = db.Table('roles_users', db.Column('user_id', db.Integer(), db.ForeignKey('user.id')), db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))

    class Role(db.Model, RoleMixin):
        id = db.Column(db.Integer(), primary_key=True)
        name = db.Column(db.String(80), unique=True)
        description = db.Column(db.String(255))

    class User(db.Model, UserMixin):
        id = db.Column(db.Integer, primary_key=True)
        api_key = db.Column(db.String(255), default=_build_api_key, unique=True)
        email = db.Column(db.String(255), unique=True)
        password = db.Column(db.String(255))
        active = db.Column(db.Boolean())
        confirmed_at = db.Column(db.DateTime())
        roles = db.relationship('Role', secondary=roles_users, backref=db.backref('users', lazy='dynamic'))

    return SQLAlchemyUserDatastore(db, User, Role)


def _build_api_key():
    raw_key = os.urandom(32)
    return base64.standard_b64encode(raw_key).decode()
