import contextlib
import sys


class StandardOutWriter:
    def write(self, _):
        pass


@contextlib.contextmanager
def suppress_stdout():
    writer = StandardOutWriter()

    stdout, stderr = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = writer, writer

    yield

    sys.stdout, sys.stderr = stdout, stderr
