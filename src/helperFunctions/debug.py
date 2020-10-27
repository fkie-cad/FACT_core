import contextlib
import sys


class _StandardOutWriter:
    def write(self, _):
        pass


@contextlib.contextmanager
def suppress_stdout():
    ''' A context manager that suppresses any output to stdout and stderr. '''
    writer = _StandardOutWriter()

    stdout, stderr = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = writer, writer

    yield

    sys.stdout, sys.stderr = stdout, stderr
