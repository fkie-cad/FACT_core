import pytest

from manage_users import start_user_management, setup_argparse, prompt_for_actions, choose_action, get_input


def test_get_input(monkeypatch):
    monkeypatch.setattr('builtins.input', lambda *x: 'my_input')

    assert get_input('') == 'my_input'

    with pytest.raises(ValueError):
        get_input('', max_len=5)
