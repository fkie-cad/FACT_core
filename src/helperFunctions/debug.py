import contextlib
import sys


class StandardOutWriter:
    def write(self, x):
        pass


class TerminalTextFormatting:
    class Format:
        BOLD = '\033[1m'
        DIM = '\033[2m'
        UNDERLINED = '\033[4m'
        BLINKING = '\033[5m'
        INVERTED = '\033[7m'
        HIDDEN = '\033[8m'

    class Color:
        BLACK = '\033[30m'
        RED = '\033[31m'
        GREEN = '\033[32m'
        YELLOW = '\033[33m'
        BLUE = '\033[34m'
        MAGENTA = '\033[35m'
        CYAN = '\033[36m'
        LIGHT_GRAY = '\033[37m'
        DEFAULT = '\033[39m'
        DARK_GRAY = '\033[90m'
        LIGHT_RED = '\033[91m'
        LIGHT_GREEN = '\033[92m'
        LIGHT_YELLOW = '\033[93m'
        LIGHT_BLUE = '\033[94m'
        LIGHT_MAGENTA = '\033[95m'
        LIGHT_CYAN = '\033[96m'
        WHITE = '\033[97m'

    class BgColor:
        BG_BLACK = '\033[40m'
        BG_RED = '\033[41m'
        BG_GREEN = '\033[42m'
        BG_YELLOW = '\033[43m'
        BG_BLUE = '\033[44m'
        BG_MAGENTA = '\033[45m'
        BG_CYAN = '\033[46m'
        BG_LIGHT_GRAY = '\033[47m'
        BG_DEFAULT = '\033[49m'
        BG_DARK_GRAY = '\033[100m'
        BG_LIGHT_RED = '\033[101m'
        BG_LIGHT_GREEN = '\033[102m'
        BG_LIGHT_YELLOW = '\033[103m'
        BG_LIGHT_BLUE = '\033[104m'
        BG_LIGHT_MAGENTA = '\033[105m'
        BG_LIGHT_CYAN = '\033[106m'
        BG_WHITE = '\033[107m'


def debug_print(message, color=TerminalTextFormatting.Color.LIGHT_RED):
    print('{}\n'.format(color), message, '{}\n'.format(TerminalTextFormatting.Color.DEFAULT))


@contextlib.contextmanager
def suppress_stdout():
    writer = StandardOutWriter()

    stdout, stderr = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = writer, writer

    yield

    sys.stdout, sys.stderr = stdout, stderr
