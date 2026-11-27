from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from multiprocessing import Process
from pathlib import Path

from test import graceful_sigterm

SRC_DIR = Path(__file__).parent.parent.parent

TEST_FILE = """
import time
from pathlib import Path

import pytest


@pytest.fixture
def resource():
    yield
    Path({torn_down!r}).touch()


def test_runs_until_terminated(resource):
    Path({started!r}).touch()
    time.sleep(60)
"""


def test_sigterm_runs_the_teardown(tmp_path):
    started, torn_down = tmp_path / 'started', tmp_path / 'torn_down'
    (tmp_path / 'conftest.py').write_text(
        'from test.graceful_sigterm import install\n\n\ndef pytest_configure():\n    install()\n'
    )
    (tmp_path / 'test_terminated.py').write_text(TEST_FILE.format(started=str(started), torn_down=str(torn_down)))
    process = subprocess.Popen(  # noqa: S603
        [sys.executable, '-m', 'pytest', '-p', 'no:cacheprovider', str(tmp_path)],
        cwd=tmp_path,
        env={**os.environ, 'PYTHONPATH': str(SRC_DIR)},
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        _wait_for(started.exists, process)
        process.send_signal(signal.SIGTERM)
        output, _ = process.communicate(timeout=30)
    finally:
        process.kill()

    assert torn_down.exists(), output.decode()
    assert 'KeyboardInterrupt' in output.decode()


def test_forked_processes_are_terminated_as_before():
    child = Process(target=time.sleep, args=(60,))
    child.start()
    child.terminate()
    child.join(timeout=10)

    assert child.exitcode == -signal.SIGTERM


def test_installed_in_this_session():
    assert signal.getsignal(signal.SIGTERM) is graceful_sigterm.handle_sigterm


def _wait_for(condition, process: subprocess.Popen, timeout: float = 30):
    end = time.time() + timeout
    while not condition():
        assert process.poll() is None, process.communicate()[0].decode()
        assert time.time() < end, 'timeout'
        time.sleep(0.1)
