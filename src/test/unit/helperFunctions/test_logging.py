import logging

from helperFunctions.logging import ColoringFormatter, TerminalColors, color_string

TEST_STRING = 'test 123'


def test_color_string():
    colored_string = color_string(TEST_STRING, TerminalColors.BLUE)
    assert colored_string.startswith(TerminalColors.BLUE)
    assert colored_string.endswith(TerminalColors.ENDC)
    assert TEST_STRING in colored_string


def test_coloring_formatter():
    formatter = ColoringFormatter(fmt='[%(levelname)s]: %(message)s')
    formatted_string = formatter.format(logging.LogRecord('foo', logging.ERROR, '', 24, TEST_STRING, (), None))
    assert formatted_string.endswith(TEST_STRING)
    assert '[{}{}{}]'.format(TerminalColors.RED, 'ERROR', TerminalColors.ENDC) in formatted_string
