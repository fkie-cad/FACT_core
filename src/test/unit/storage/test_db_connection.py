import multiprocessing

from storage.db_connection import ReadOnlyConnection


class _FakeEngine:
    def __init__(self):
        self.dispose_called_with = None

    def dispose(self, close=True):
        self.dispose_called_with = close


def _child_verify_dispose(fake_engine, queue):
    # the after_in_child callback should run during os.fork() and call dispose
    queue.put(fake_engine.dispose_called_with)


def test_engine_registered_on_init(backend_config, monkeypatch):
    fresh_engines: set = set()
    monkeypatch.setattr('storage.db_connection._engines', fresh_engines)
    conn = ReadOnlyConnection()
    assert conn.engine in fresh_engines


def test_engines_disposed_after_fork(monkeypatch):
    fake_engine = _FakeEngine()
    monkeypatch.setattr('storage.db_connection._engines', {fake_engine})

    ctx = multiprocessing.get_context('fork')
    queue = ctx.Queue()
    proc = ctx.Process(target=_child_verify_dispose, args=(fake_engine, queue))
    proc.start()
    proc.join(timeout=10)
    assert proc.exitcode == 0, 'child process did not exit cleanly'

    result = queue.get(timeout=5)
    assert result is False, f'expected dispose(close=False), got dispose(close={result!r})'
