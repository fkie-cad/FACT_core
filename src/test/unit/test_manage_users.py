import pytest

from manage_users import start_user_management, setup_argparse, prompt_for_actions, choose_action, get_input
from flask import Flask


def test_get_input(monkeypatch):
    monkeypatch.setattr('builtins.input', lambda *x: 'my_input')

    assert get_input('') == 'my_input', 'bad processing of input'

    with pytest.raises(ValueError):
        get_input('', max_len=5)


def test_choose_action(monkeypatch):
    monkeypatch.setattr('builtins.input', lambda *x: 'my_input')

    assert choose_action() == 'my_input', 'bad processing of input'


def test_setup_argparse(monkeypatch):
    monkeypatch.setattr('sys.argv', ['function_name', '/path/to/some/file'])
    args = setup_argparse()
    assert args.config_file == '/path/to/some/file', 'bad propagation of config path'


def test_prompt_for_actions(monkeypatch):
    input_sequence = ['help', 'bad_action', 'exit']
    monkeypatch.setattr('builtins.input', lambda *x: input_sequence.pop(0))

    prompt_for_actions(None, None, None)

    assert True, 'test will throw exception or stall if something is broken'


def test_start_user_management(monkeypatch):
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///'

    input_sequence = ['create_role', 'role', 'exit']
    monkeypatch.setattr('builtins.input', lambda *x: input_sequence.pop(0))

    start_user_management(app)

    assert True, 'test will throw exception or stall if something is broken'
