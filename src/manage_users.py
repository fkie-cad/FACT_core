#!/usr/bin/env python3

import argparse
import getpass
import os
import sys

from flask_security import Security
from flask_sqlalchemy import SQLAlchemy
from prompt_toolkit.completion import WordCompleter

from config.ascii import FACT_ASCII_ART
from helperFunctions.config import load_config, get_config_dir
from helperFunctions.terminal import SESSION, ActionValidator, ActionValidatorReverse
from helperFunctions.web_interface import password_is_legal
from version import __VERSION__
from web_interface.frontend_main import WebFrontEnd
from web_interface.security.authentication import create_user_interface
from web_interface.security.privileges import ROLES


def setup_argparse():
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--version', action='version',
                        version='FACT User Management (FACTUM) {}'.format(__VERSION__))
    parser.add_argument('-C', '--config_file', help='set path to config File',
                        default='{}/main.cfg'.format(get_config_dir()))
    return parser.parse_args()


def get_input(message, max_len=25):
    while True:
        user_input = input(message)
        if len(user_input) > max_len:
            raise ValueError('Error: input too long (max length: {})'.format(max_len))
        else:
            return user_input


def choose_action():
    print('\nPlease choose an action (use "help" for a list of available actions)')
    chosen_action = input('action: ')
    return chosen_action


class Actions:
    @staticmethod
    def help(*_):
        print(
            '\nOne of the following actions can be chosen:\n'
            '\n\t[create_user]\t\tcreate new user'
            '\n\t[delete_user]\t\tdelete a user'
            '\n\t[create_role]\t\tcreate new role'
            '\n\t[add_role_to_user]\tadd existing role to an existing user'
            '\n\t[remove_role_from_user]\tremove role from user'
            '\n\t[get_apikey_for_user]\tretrieve apikey for existing user'
            '\n\t[help]\t\t\tshow this help'
            '\n\t[exit]\t\t\tclose application'
        )

    @staticmethod
    def _user_exists(app, interface, name):
        with app.app_context():
            user = interface.find_user(email=name)
        return True if user else False

    @staticmethod
    def _role_exists(app, interface, role):
        with app.app_context():
            exists = interface.find_role(role)
        return True if exists else False

    @staticmethod
    def _get_user_list(app, interface):
        with app.app_context():
            return [x.email for x in interface.list_users()]

    @staticmethod
    def _get_role_list(app, interface):
        with app.app_context():
            return [x.name for x in interface.list_roles()]

    @staticmethod
    def exit(*_):
        raise EOFError('Quitting ..')

    @staticmethod
    def _old_create_user(app, interface, db):
        user = get_input('username: ')
        assert not Actions._user_exists(app, interface, user), 'user must not exist'

        password = getpass.getpass('password: ')
        assert password_is_legal(password), 'password is illegal'
        with app.app_context():
            interface.create_user(email=user, password=password)
            db.session.commit()

    @staticmethod
    def create_user(app, interface, db):
        user_list = Actions._get_user_list(app, interface)
        user = SESSION.prompt(
            'username: ',
            validator=ActionValidatorReverse(user_list, message='user must not exist')
        )
        password = getpass.getpass('password: ')
        assert password_is_legal(password), 'password is illegal'
        with app.app_context():
            interface.create_user(email=user, password=password, roles=['guest'])
            db.session.commit()

    @staticmethod
    def _old_get_apikey_for_user(app, interface, _):
        user = get_input('username: ')
        assert Actions._user_exists(app, interface, user), 'user must exist to retrieve apikey'

        with app.app_context():
            user = interface.find_user(email=user)

        apikey = user.api_key
        print('key: {}'.format(apikey))

    @staticmethod
    def get_apikey_for_user(app, interface, db):
        user_list = Actions._get_user_list(app, interface)
        action_completer = WordCompleter(user_list)
        user = SESSION.prompt(
            'username: ',
            validator=ActionValidator(user_list, message='user must exist to retrieve apikey.'),
            completer=action_completer
        )
        with app.app_context():
            user = interface.find_user(email=user)

        apikey = user.api_key
        print('key: {}'.format(apikey))

    @staticmethod
    def _old_create_role(app, interface, db):
        role = get_input('role name: ')
        with app.app_context():
            interface.create_role(name=role)
            db.session.commit()

    @staticmethod
    def create_role(app, interface, db):
        role_list = Actions._get_role_list(app, interface)
        role = SESSION.prompt(
            'role name: ',
            validator=ActionValidatorReverse(role_list, message='role must not exist')
        )
        with app.app_context():
            if not Actions._role_exists(app, interface, role):
                interface.create_role(name=role)
                db.session.commit()

    @staticmethod
    def _old_add_role_to_user(app, interface, db):
        user = get_input('username: ')
        assert Actions._user_exists(app, interface, user), 'user must exists before adding it to role'

        role = get_input('role name: ')
        assert Actions._role_exists(app, interface, role), 'role must exists before user can be added'

        with app.app_context():
            interface.add_role_to_user(user=interface.find_user(email=user), role=role)
            db.session.commit()

    @staticmethod
    def add_role_to_user(app, interface, db):
        user_list = Actions._get_user_list(app, interface)
        role_list = Actions._get_role_list(app,interface)
        user_completer = WordCompleter(user_list)
        role_completer = WordCompleter(role_list)
        user = SESSION.prompt(
            'username: ',
            validator=ActionValidator(user_list, message='user must exists before adding it to a role'),
            completer=user_completer
        )
        role = SESSION.prompt(
            'rolename: ',
            validator=ActionValidator(role_list, message='role must exists before user can be added'),
            completer=role_completer
        )
        with app.app_context():
            interface.add_role_to_user(user=interface.find_user(email=user), role=role)
            db.session.commit()

    @staticmethod
    def _old_remove_role_from_user(app, interface, db):
        user = get_input('username: ')
        assert Actions._user_exists(app, interface, user), 'user must exists before adding it to role'

        role = get_input('role name: ')
        assert Actions._role_exists(app, interface, role), 'role must exists before user can be added'

        with app.app_context():
            interface.remove_role_from_user(user=interface.find_user(email=user), role=role)
            db.session.commit()

    @staticmethod
    def remove_role_from_user(app, interface, db):
        user_list = Actions._get_user_list(app, interface)
        user_completer = WordCompleter(user_list)
        user = SESSION.prompt(
            'username: ',
            validator=ActionValidator(user_list, message='user must exist'),
            completer=user_completer
        )
        role = SESSION.prompt(
            'rolename: ',
            validator=ActionValidator(user.roles, message='user must have that role before it can be removed'),
            completer=WordCompleter(user.roles)
        )
        with app.app_context():
            interface.remove_role_from_user(user=interface.find_user(email=user), role=role)
            db.session.commit()

    @staticmethod
    def _old_delete_user(app, interface, db):
        user = get_input('username: ')
        assert Actions._user_exists(app, interface, user), 'user must exists'

        with app.app_context():
            interface.delete_user(user=interface.find_user(email=user))
            db.session.commit()

    @staticmethod
    def delete_user(app, interface, db):
        user_list = Actions._get_user_list(app, interface)
        action_completer = WordCompleter(user_list)
        user = SESSION.prompt(
            'username: ',
            validator=ActionValidator(user_list, message='user must exist before deleting'),
            completer=action_completer
        )
        with app.app_context():
            interface.delete_user(user=interface.find_user(email=user))
            db.session.commit()


LEGAL_ACTIONS = [action for action in dir(Actions) if not action.startswith('_')]


def initialise_roles(app, interface, db):
    for role in ROLES:
        if not interface.find_role(role):
            with app.app_context():
                interface.create_role(name=role)
                db.session.commit()


def _old_prompt_for_actions(app, store, db):
    print(FACT_ASCII_ART)

    print('\nWelcome to the FACT User Management (FACTUM)\n')

    while True:
        try:
            action = choose_action()
        except (EOFError, KeyboardInterrupt):
            break
        if action not in LEGAL_ACTIONS:
            print('error: please choose a legal action.')
        else:
            try:
                acting_function = getattr(Actions, action)
                acting_function(app, store, db)
            except AssertionError as assertion_error:
                print('error: {}'.format(assertion_error))
            except EOFError:
                break

    print('\nQuitting ..')


def prompt_toolkit_stuff(app, store, db):
    print(FACT_ASCII_ART)
    print('\nWelcome to the FACT User Management (FACTUM)\n')
    initialise_roles(app, store, db)

    while True:
        try:
            action_completer = WordCompleter(LEGAL_ACTIONS)
            action = SESSION.prompt(
                'Please choose an action to perform: ',
                validator=ActionValidator(LEGAL_ACTIONS),
                completer=action_completer
            )
        except (EOFError, KeyboardInterrupt):
            break
        try:
            acting_function = getattr(Actions, action)
            acting_function(app, store, db)

        except KeyboardInterrupt:
            print('returning to action selection\n\n')
        except AssertionError as assertion_error:
            print('error: {}'.format(assertion_error))
        except EOFError:
            break

    print('\nQuitting ..')

    pass


def start_user_management(app):
    db = SQLAlchemy(app)
    Security(app)
    store = create_user_interface(db)

    db.create_all()

    prompt_toolkit_stuff(app, store, db)


def main():
    args = setup_argparse()

    file_name = os.path.basename(args.config_file)
    print(file_name)
    config = load_config(file_name)
    frontend = WebFrontEnd(config)

    start_user_management(frontend.app)

    return 0


if __name__ == '__main__':
    sys.exit(main())
