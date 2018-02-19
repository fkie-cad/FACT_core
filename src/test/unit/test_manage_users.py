import pytest

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
    monkeypatch.setattr('sys.argv', ['function_name', '/path/to/some/file'])
    args = setup_argparse()
    assert args.config_file == '/path/to/some/file', 'bad propagation of config path'
