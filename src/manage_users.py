#!/usr/bin/env python3

import argparse
import getpass
import sys
from pathlib import Path

from flask_security.utils import hash_password
from prompt_toolkit.completion import WordCompleter
from web_interface.security.terminal_validators import SESSION, ActionValidator, ActionValidatorReverse

from config.ascii import FACT_ASCII_ART
from helperFunctions.config import get_config_dir, load_config
from helperFunctions.web_interface import password_is_legal
from version import __VERSION__
from web_interface.frontend_main import WebFrontEnd
from web_interface.security.privileges import ROLES


def setup_argparse():
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--version', action='version',
                        version=f'FACT User Management (FACTUM) {__VERSION__}')
    parser.add_argument('-C', '--config_file', help='set path to config File',
                        default=f'{get_config_dir()}/main.cfg')
    return parser.parse_args()


def get_input(message, max_len=25):
    while True:
        user_input = input(message)
        if len(user_input) > max_len:
            raise ValueError(f'Error: input too long (max length: {max_len})')
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
            '\n\t[add_role_to_user]\tadd existing role to an existing user'
            '\n\t[create_role]\t\tcreate new role'
            '\n\t[create_user]\t\tcreate new user'
            '\n\t[delete_user]\t\tdelete a user'
            '\n\t[get_apikey_for_user]\tretrieve apikey for existing user'
            '\n\t[list_all_users]\tlist all existing users and their roles'
            '\n\t[remove_role_from_user]\tremove role from user'
            '\n\t[help]\t\t\tshow this help'
            '\n\t[exit]\t\t\tclose application'
        )

    @staticmethod
    def _user_exists(app, interface, name):
        with app.app_context():
            user = interface.find_user(email=name)
        return bool(user)

    @staticmethod
    def _role_exists(app, interface, role):
        with app.app_context():
            exists = interface.find_role(role)
        return bool(exists)

    @staticmethod
    def _get_user_list(app, interface):
        with app.app_context():
            return [x.email for x in interface.list_users()]

    @staticmethod
    def _get_role_list(app, interface):
        with app.app_context():
            return [x.name for x in interface.list_roles()]

    @staticmethod
    def create_user(app, interface, db):
        user_list = Actions._get_user_list(app, interface)
        user = SESSION.prompt(
            'username: ',
            validator=ActionValidatorReverse(user_list, message='user must not exist'),
            completer=None
        )
        while True:
            password = getpass.getpass('password: ')
            if not password_is_legal(password):
                print('Password is not legal. Please choose another password.')
                continue
            break
        with app.app_context():
            interface.create_user(email=user, password=hash_password(password))
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
    def add_role_to_user(app, interface, db):
        user_list = Actions._get_user_list(app, interface)
        role_list = Actions._get_role_list(app, interface)
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
    def remove_role_from_user(app, interface, db):
        user_list = Actions._get_user_list(app, interface)
        user_completer = WordCompleter(user_list)
        user = SESSION.prompt(
            'username: ',
            validator=ActionValidator(user_list, message='user must exist'),
            completer=user_completer
        )
        user = interface.find_user(email=user)
        user_roles = [role.name for role in user.roles]
        role = SESSION.prompt(
            'rolename: ',
            validator=ActionValidator(user_roles, message='user must have that role before it can be removed'),
            completer=WordCompleter(user_roles)
        )
        with app.app_context():
            interface.remove_role_from_user(user=interface.find_user(email=user.email), role=role)
            db.session.commit()

    @staticmethod
    def get_apikey_for_user(app, interface, _):
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
        print(f'key: {apikey}')

    @staticmethod
    def list_all_users(_, interface, __):
        user_list = interface.list_users()
        for user in user_list:
            user_roles = ', '.join([role.name for role in user.roles])
            print(f'\n\t{user.email} ({user_roles})')
        print()

    @staticmethod
    def exit(*_):
        raise EOFError('Quitting ..')


LEGAL_ACTIONS = [action for action in dir(Actions) if not action.startswith('_')]


def initialise_roles(app, interface, db):
    for role in ROLES:
        if not interface.find_role(role):
            with app.app_context():
                interface.create_role(name=role)
                db.session.commit()


def prompt_loop(app, store, db):
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
            print('returning to action selection')
        except AssertionError as assertion_error:
            print(f'error: {assertion_error}')
        except EOFError:
            break

    print('\nQuitting ..')


def start_user_management(app, store, db):
    # We expect flask-security to be initialized
    db.create_all()
    prompt_loop(app, store, db)


def main():
    args = setup_argparse()

    file_name = Path(args.config_file).name
    config = load_config(file_name)
    frontend = WebFrontEnd(config)

    start_user_management(frontend.app, frontend.user_datastore, frontend.user_db)

    return 0


if __name__ == '__main__':
    sys.exit(main())
