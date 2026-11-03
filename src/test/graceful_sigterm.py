"""
Make SIGTERM stop a test run like Ctrl-C (``KeyboardInterrupt``), so that pytest runs the teardown of the fixtures.
Without it, a terminated pytest leaves the backend processes and extractor containers of its fixtures running, and
they break later test runs (see `test/leftovers.py`). SIGKILL cannot be handled.
"""

from __future__ import annotations

import os
import signal
import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from types import FrameType

_main_pid: int | None = None
#: whether `_before_fork` replaced the handler (`_after_fork_in_parent` puts it back)
_paused = False


def install() -> None:
    """Handle SIGTERM in this (the pytest main) process; forked processes keep the default behaviour"""
    global _main_pid  # noqa: PLW0603
    if _main_pid is None:
        os.register_at_fork(before=_before_fork, after_in_parent=_after_fork_in_parent, after_in_child=_restore_default)
    _main_pid = os.getpid()
    signal.signal(signal.SIGTERM, handle_sigterm)


def handle_sigterm(signum: int, frame: FrameType | None) -> None:
    del frame
    if os.getpid() != _main_pid:  # forked from another thread and terminated before `_restore_default` ran
        _restore_default()
        os.kill(os.getpid(), signum)
        return
    raise KeyboardInterrupt('SIGTERM')


def _before_fork() -> None:
    # A child gets the default behaviour already with the fork: CPython drops signals that reach the child before its
    # `after_in_child` hooks have run, so a child terminated right after its start would keep running.
    # `signal.signal` only works in the main thread: forks from other threads rely on `after_in_child`.
    global _paused  # noqa: PLW0603
    _paused = _is_main_thread() and signal.getsignal(signal.SIGTERM) is handle_sigterm
    if _paused:
        signal.signal(signal.SIGTERM, signal.SIG_DFL)


def _after_fork_in_parent() -> None:
    global _paused  # noqa: PLW0603
    if _paused and _is_main_thread():
        signal.signal(signal.SIGTERM, handle_sigterm)
    _paused = False


def _is_main_thread() -> bool:
    return threading.current_thread() is threading.main_thread()


def _restore_default() -> None:
    if signal.getsignal(signal.SIGTERM) is handle_sigterm:
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
