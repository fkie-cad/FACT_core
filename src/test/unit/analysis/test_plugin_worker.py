import ctypes
from multiprocessing import Array, Queue, Value
from pathlib import Path
from tempfile import NamedTemporaryFile
from time import sleep

from pydantic import BaseModel
from semver import Version

from analysis.plugin import AnalysisFailedError, AnalysisPluginV0
from scheduler.analysis.plugin import PluginRunner, Worker
from test.common_helper import create_test_file_object


class NormalPlugin(AnalysisPluginV0):
    class Schema(BaseModel):
        foo: str

    def __init__(self):
        metadata = self.MetaData(
            name=self.__class__.__name__,
            description='',
            Schema=self.Schema,
            version=Version(0, 1, 0),
        )
        super().__init__(metadata)

    def analyze(self, file_handle, virtual_file_path, analyses):
        return self.Schema(foo='foo')


def _get_worker(plugin, timeout=5):
    in_queue, out_queue = Queue(), Queue()
    stats = Array(ctypes.c_float, 10)
    stats_count = Value('i', 0)
    stats_index = Value('i', 0)
    worker_config = Worker.Config(timeout=timeout)
    worker = Worker(plugin, worker_config, in_queue, out_queue, stats, stats_count, stats_index)
    worker.SIGTERM_TIMEOUT = 0.1
    return worker


def _run_worker(worker: Worker):
    with NamedTemporaryFile() as temp_file:
        Path(temp_file.name).write_text('foo')
        test_fo = create_test_file_object()
        task = PluginRunner.Task(virtual_file_path={}, path=temp_file.name, dependencies={}, scheduler_state=test_fo)
        worker._in_queue.put(task)
        worker.start()
        try:
            return worker._out_queue.get(timeout=10)
        finally:
            worker.terminate()


def test_worker():
    plugin = NormalPlugin()
    worker = _get_worker(plugin)
    output_fo = _run_worker(worker)

    assert plugin.metadata.name in output_fo.processed_analysis
    assert output_fo.processed_analysis[plugin.metadata.name]['result'] == {'foo': 'foo'}


class TimeoutPlugin(NormalPlugin):
    def analyze(self, file_handle, virtual_file_path, analyses):
        sleep(10)


def test_worker_timeout():
    plugin = TimeoutPlugin()
    worker = _get_worker(plugin, timeout=1)
    output_fo = _run_worker(worker)

    analysis_exception = getattr(output_fo, 'analysis_exception', None)
    assert analysis_exception is not None
    plugin_name, error = analysis_exception
    assert plugin_name == plugin.metadata.name
    assert error == 'Analysis timed out'


class ExceptionPlugin(NormalPlugin):
    def analyze(self, file_handle, virtual_file_path, analyses):
        raise Exception('unknown exception')


def test_worker_exception():
    plugin = ExceptionPlugin()
    worker = _get_worker(plugin)
    output_fo = _run_worker(worker)

    analysis_exception = getattr(output_fo, 'analysis_exception', None)
    assert analysis_exception is not None
    plugin_name, error = analysis_exception
    assert plugin_name == plugin.metadata.name
    assert error == 'Exception occurred during analysis'


class FailPlugin(NormalPlugin):
    def analyze(self, file_handle, virtual_file_path, analyses):
        raise AnalysisFailedError('reason')


def test_worker_failed():
    plugin = FailPlugin()
    worker = _get_worker(plugin)
    output_fo = _run_worker(worker)

    analysis_exception = getattr(output_fo, 'analysis_exception', None)
    assert analysis_exception is not None
    plugin_name, error = analysis_exception
    assert plugin_name == plugin.metadata.name
    assert error == 'Analysis failed: reason'
