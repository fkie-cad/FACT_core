import os

from flask_security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin
from flask_sqlalchemy import SQLAlchemy


def add_flask_security_to_app(app):
    # Create app
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECURITY_PASSWORD_SALT'] = os.urandom(24)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://'

    # Create database connection object
    db = SQLAlchemy(app)

    # Define models
    roles_users = db.Table('roles_users', db.Column('user_id', db.Integer(), db.ForeignKey('user.id')), db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))

    class Role(db.Model, RoleMixin):
        id = db.Column(db.Integer(), primary_key=True)
        name = db.Column(db.String(80), unique=True)
        description = db.Column(db.String(255))

    class User(db.Model, UserMixin):
        id = db.Column(db.Integer, primary_key=True)
        email = db.Column(db.String(255), unique=True)
        password = db.Column(db.String(255))
        active = db.Column(db.Boolean())
        confirmed_at = db.Column(db.DateTime())
        roles = db.relationship('Role', secondary=roles_users,
                                backref=db.backref('users', lazy='dynamic'))

    # Setup Flask-Security
    user_datastore = SQLAlchemyUserDatastore(db, User, Role)
    security = Security(app, user_datastore)

    # Create a user to test with
    @app.before_first_request
    def create_user():
        db.create_all()
        user_datastore.create_user(email='test', password='test')
        user_datastore.activate_user(user_datastore.find_user(email='test'))
        user_datastore.create_role(name='superuser')
        user_datastore.add_role_to_user(user=user_datastore.find_user(email='test'), role='superuser')
        db.session.commit()

    return user_datastore, security
