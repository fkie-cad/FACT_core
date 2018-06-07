import logging

from helperFunctions.debug import suppress_stdout, pipe_stdout_to_debug


def print_foo():
    print('foo', end='')


def test_suppress_stdout(capsys):
    print_foo()

    without_decorator = capsys.readouterr()
    assert without_decorator.out == 'foo'

    with suppress_stdout():
        print_foo()

    with_decorator = capsys.readouterr()
    assert not with_decorator.out


def test_pipe_stdout_to_debug(caplog):
    with caplog.at_level(logging.DEBUG):
        with pipe_stdout_to_debug():
            print_foo()

        assert all(string in caplog.text for string in ['DEBUG', 'Suppressed', 'foo'])
