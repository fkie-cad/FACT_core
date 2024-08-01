from typing import NamedTuple

import pytest
from prompt_toolkit import PromptSession
from prompt_toolkit.input import create_pipe_input
from prompt_toolkit.input.base import PipeInput
from prompt_toolkit.output import DummyOutput

from fact.manage_users import setup_argparse, start_user_management
from fact.web_interface.app import create_app
from fact.web_interface.security.authentication import add_flask_security_to_app

use_memory_db = pytest.mark.frontend_config_overwrite(
    {
        'authentication': {
            'enabled': True,
            'user_database': 'sqlite://',
            'password_salt': 'salt',
        },
    }
)


class Prompt(NamedTuple):
    session: PromptSession
    input: PipeInput


@pytest.fixture
def prompt(monkeypatch):
    monkeypatch.setattr('getpass.getpass', lambda _: 'mock_password')
    with create_pipe_input() as pipe:
        session = PromptSession(
            input=pipe,
            output=DummyOutput(),
        )
        if session.input.fileno() >= 1024:  # noqa: PLR2004
            pytest.skip('FixMe: Skipping because of too many open files')
        yield Prompt(session, pipe)


def test_setup_argparse(monkeypatch):
    monkeypatch.setattr('sys.argv', ['function_name', '-C', '/path/to/some/file'])
    args = setup_argparse()
    assert args.config_file == '/path/to/some/file', 'bad propagation of config path'


def _setup_frontend():
    # See add_config_from_configparser_to_app for needed values
    test_app = create_app()
    db, store = add_flask_security_to_app(test_app)
    return test_app, store, db


@pytest.mark.parametrize(
    'action_and_inputs',
    [
        ['help'],
        ['create_role', 'role'],
        ['create_user', 'username'],
        ['create_user', 'A', 'create_user', 'B'],
        ['create_user', 'username', 'get_apikey_for_user', 'username'],
        ['create_user', 'username', 'delete_user', 'username'],
        ['create_role', 'role', 'create_user', 'username', 'add_role_to_user', 'username', 'role'],
        [
            'create_role',
            'role',
            'create_user',
            'username',
            'add_role_to_user',
            'username',
            'role',
            'remove_role_from_user',
            'username',
            'role',
        ],
        ['create_user', 'username', 'list_all_users'],
    ],
)
@use_memory_db
def test_integration_try_actions(action_and_inputs, prompt):
    action_and_inputs.append('exit')
    for action in action_and_inputs:
        prompt.input.send_text(f'{action}\n')
    test_app, store, db = _setup_frontend()
    start_user_management(test_app, store, db, prompt.session)

    # test will throw exception or stall if something is broken
    assert True, f'action sequence {action_and_inputs} caused error'


@use_memory_db
def test_add_role(prompt, capsys):
    action_and_inputs = [
        'create_user',
        'test_user',
        'list_all_users',
        'add_role_to_user',
        'test_user',
        'guest_analyst',
        'list_all_users',
        'exit',
    ]
    for action in action_and_inputs:
        prompt.input.send_text(f'{action}\n')
    test_app, store, db = _setup_frontend()
    start_user_management(test_app, store, db, prompt.session)

    captured = capsys.readouterr()
    assert 'test_user (guest)' in captured.out
    assert 'test_user (guest, guest_analyst)' in captured.out


@use_memory_db
def test_password_is_hashed(prompt):
    action_and_inputs = ['create_user', 'test_user', 'exit']
    for action in action_and_inputs:
        prompt.input.send_text(f'{action}\n')
    test_app, store, db = _setup_frontend()
    start_user_management(test_app, store, db, prompt.session)
    with test_app.app_context():
        user = store.find_user(email='test_user')
    assert user.password != 'mock_password'
