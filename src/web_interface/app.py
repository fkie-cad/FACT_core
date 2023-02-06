import os

from flask import Flask
from flask_security import uia_username_mapper

from config import cfg


def create_app():
    app = Flask(__name__)
    app.config.from_object(__name__)
    app.config['SECRET_KEY'] = os.urandom(24)
    _add_config_to_app(app)
    return app


def _add_config_to_app(app):
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECURITY_PASSWORD_SALT'] = cfg.data_storage.password_salt.encode()
    app.config['SQLALCHEMY_DATABASE_URI'] = cfg.data_storage.user_database
    # FIXME fix redirect loop here
    app.config['SECURITY_UNAUTHORIZED_VIEW'] = '/login'
    app.config['LOGIN_DISABLED'] = not cfg.expert_settings.authentication

    # rename session cookie to fix user session problems with other flask apps running on the same system
    app.config['SESSION_COOKIE_NAME'] = 'FACT_session_cookie'

    # As we want to use ONLY usernames and no emails but email is hardcoded in
    # flask-security we change the validation mapper of 'email'.
    # Note that from the perspective of flask-security we still use emails.
    # This means that we do not want to enable SECURITY_USERNAME_ENABLE
    app.config['SECURITY_USER_IDENTITY_ATTRIBUTES'] = [
        {'email': {'mapper': uia_username_mapper, 'case_insensitive': True}}
    ]
