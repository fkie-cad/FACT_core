from helperFunctions.debug import suppress_stdout


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
