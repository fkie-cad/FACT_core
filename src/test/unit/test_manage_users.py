import pytest
from flask import Flask

from manage_users import start_user_management, setup_argparse, prompt_for_actions, choose_action, get_input


def test_get_input(monkeypatch):
    monkeypatch.setattr('builtins.input', lambda *x: 'my_input')

    assert get_input('') == 'my_input', 'bad processing of input'

    with pytest.raises(ValueError):
        get_input('', max_len=5)


def test_choose_action(monkeypatch):
    monkeypatch.setattr('builtins.input', lambda *x: 'my_input')

    assert choose_action() == 'my_input', 'bad processing of input'


def test_setup_argparse(monkeypatch):
    monkeypatch.setattr('sys.argv', ['function_name', '-C', '/path/to/some/file'])
    args = setup_argparse()
    assert args.config_file == '/path/to/some/file', 'bad propagation of config path'


def test_prompt_for_actions(monkeypatch):
    input_sequence = ['help', 'bad_action', 'exit']
    monkeypatch.setattr('builtins.input', lambda *x: input_sequence.pop(0))

    prompt_for_actions(None, None, None)

    assert True, 'test will throw exception or stall if something is broken'


@pytest.mark.parametrize('action_and_inputs', [
    ['help', ],
    ['create_role', 'role'],
    ['create_user', 'username'],
    ['create_user', 'username', 'create_user', 'username'],
    ['create_user', 'A', 'create_user', 'B'],
    ['create_user', 'username', 'get_apikey_for_user', 'username'],
    ['create_user', 'username', 'delete_user', 'username'],
    ['create_role', 'role', 'create_user', 'username', 'add_role_to_user', 'username', 'role'],
    ['create_role', 'role', 'create_user', 'username', 'add_role_to_user', 'username', 'role', 'remove_role_from_user', 'username', 'role']
])
def test_integration_try_actions(monkeypatch, action_and_inputs):
    action_and_inputs.append('exit')
    monkeypatch.setattr('builtins.input', lambda *x: action_and_inputs.pop(0))
    monkeypatch.setattr('getpass.getpass', lambda *x: 'mock_password')

    test_app = Flask(__name__)
    test_app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///'
    test_app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    start_user_management(test_app)

    assert True, 'test will throw exception or stall if something is broken'
