from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import NamedTemporaryFile
from time import sleep

import pytest

from fact.intercom.back_end_binding import (
    InterComBackEndAnalysisPlugInsPublisher,
    InterComBackEndAnalysisTask,
    InterComBackEndBinarySearchTask,
    InterComBackEndCompareTask,
    InterComBackEndFileDiffTask,
    InterComBackEndLogsTask,
    InterComBackEndPeekBinaryTask,
    InterComBackEndRawDownloadTask,
    InterComBackEndReAnalyzeTask,
    InterComBackEndSingleFileTask,
    InterComBackEndTarRepackTask,
)
from fact.intercom.front_end_binding import InterComFrontEndBinding
from fact.test.common_helper import create_test_firmware


class AnalysisServiceMock:
    def get_plugin_dict(self):
        return {'dummy': 'dummy description'}


@pytest.fixture
def intercom_frontend():
    _intercom_frontend = InterComFrontEndBinding()
    yield _intercom_frontend
    _intercom_frontend.redis.redis.flushdb()


class BinaryServiceMock:
    def __init__(self, *_, **__):
        pass

    @staticmethod
    def get_binary_and_file_name(uid: str) -> tuple[bytes, str]:
        if uid == 'uid1':
            return b'binary content 1', 'file_name_1'
        if uid == 'uid2':
            return b'binary content 2', 'file_name_2'
        raise AssertionError('if this line reached something went wrong')


@pytest.mark.frontend_config_overwrite(
    {
        'communication_timeout': '1',
    }
)
class TestInterComTaskCommunication:
    def test_analysis_task(self, intercom_frontend):
        task_listener = InterComBackEndAnalysisTask()
        test_fw = create_test_firmware()
        test_fw.file_path = None
        intercom_frontend.add_analysis_task(test_fw)
        task = task_listener.get_next_task()

        assert task.uid == test_fw.uid, 'uid not correct'
        assert task.file_path is not None, 'file_path not set'
        assert Path(task.file_path).exists(), 'file does not exist'

    def test_single_file_task(self, intercom_frontend):
        task_listener = InterComBackEndSingleFileTask()
        test_fw = create_test_firmware()
        test_fw.file_path = None
        test_fw.scheduled_analysis = ['binwalk']
        intercom_frontend.add_single_file_task(test_fw)
        task = task_listener.get_next_task()

        assert task.uid == test_fw.uid, 'uid not transported correctly'
        assert task.scheduled_analysis

    def test_re_analyze_task(self, intercom_frontend):
        task_listener = InterComBackEndReAnalyzeTask()
        test_fw = create_test_firmware()
        test_fw.file_path = None
        intercom_frontend.add_re_analyze_task(test_fw)
        task = task_listener.get_next_task()
        assert task.uid == test_fw.uid, 'uid not correct'

    def test_compare_task(self, intercom_frontend):
        task = InterComBackEndCompareTask()
        intercom_frontend.add_compare_task('valid_id', force=False)
        result = task.get_next_task()
        assert result == ('valid_id', False)

    def test_analysis_plugin_publication(self, intercom_frontend):
        _ = InterComBackEndAnalysisPlugInsPublisher(analysis_service=AnalysisServiceMock())
        plugins = intercom_frontend.get_available_analysis_plugins()
        assert len(plugins) == 1, 'Not all plug-ins found'
        assert plugins == {'dummy': 'dummy description'}, 'content not correct'

    def test_analysis_plugin_publication_not_available(self, intercom_frontend):
        with pytest.raises(RuntimeError):
            intercom_frontend.get_available_analysis_plugins()

    def test_raw_download_task(self, monkeypatch, intercom_frontend):
        monkeypatch.setattr(
            'intercom.back_end_binding.BinaryService.get_binary_and_file_name', lambda *_: (b'test', 'test.txt')
        )
        monkeypatch.setattr('intercom.front_end_binding.generate_task_id', lambda *_: 'valid_uid_0.0')

        result = intercom_frontend.get_binary_and_filename('valid_uid')
        assert result is None, 'should be none because of timeout'

        task_listener = InterComBackEndRawDownloadTask()
        task = task_listener.get_next_task()
        assert task == 'valid_uid', 'task not correct'
        result = intercom_frontend.get_binary_and_filename('valid_uid_0.0')
        assert result == (b'test', 'test.txt'), 'retrieved binary not correct'

    def test_file_diff_task(self, monkeypatch, intercom_frontend):
        monkeypatch.setattr('intercom.front_end_binding.generate_task_id', lambda _: 'valid_uid_0.0')
        monkeypatch.setattr('intercom.back_end_binding.BinaryService', BinaryServiceMock)

        result = intercom_frontend.get_file_diff(('uid1', 'uid2'))
        assert result is None, 'should be None because of timeout'

        task_listener = InterComBackEndFileDiffTask()
        task = task_listener.get_next_task()
        assert task == ('uid1', 'uid2'), 'task not correct'
        result = intercom_frontend.get_file_diff(('uid1', 'uid2'))
        expected_diff = '--- file_name_1\n+++ file_name_2\n@@ -1 +1 @@\n-binary content 1+binary content 2'
        assert result == expected_diff, 'file diff not correct'

    def test_peek_binary_task(self, monkeypatch, intercom_frontend):
        monkeypatch.setattr('intercom.back_end_binding.BinaryService.read_partial_binary', lambda *_: b'foobar')
        monkeypatch.setattr('intercom.front_end_binding.generate_task_id', lambda *_: 'valid_uid_0.0')

        result = intercom_frontend.peek_in_binary('valid_uid', 0, 512)
        assert result is None, 'should be none because of timeout'

        task_listener = InterComBackEndPeekBinaryTask()
        task = task_listener.get_next_task()
        assert task == ('valid_uid', 0, 512), 'task not correct'
        result = intercom_frontend.peek_in_binary('valid_uid', 0, 512)
        assert result == b'foobar', 'retrieved binary not correct'

    def test_tar_repack_task(self, intercom_frontend, monkeypatch):
        monkeypatch.setattr(
            'intercom.back_end_binding.BinaryService.get_repacked_binary_and_file_name',
            lambda *_: (b'test', 'test.tar'),
        )
        monkeypatch.setattr('intercom.front_end_binding.generate_task_id', lambda *_: 'valid_uid_0.0')

        result = intercom_frontend.get_repacked_binary_and_file_name('valid_uid')
        assert result is None, 'should be none because of timeout'

        task_listener = InterComBackEndTarRepackTask()
        task = task_listener.get_next_task()
        assert task == 'valid_uid', 'task not correct'
        result = intercom_frontend.get_repacked_binary_and_file_name('valid_uid_0.0')
        assert result == (b'test', 'test.tar'), 'retrieved binary not correct'

    def test_binary_search_task(self, intercom_frontend, monkeypatch):
        yara_rule, expected_result = b'yara rule', 'result'
        monkeypatch.setattr(
            'intercom.back_end_binding.YaraBinarySearchScanner.get_binary_search_result', lambda *_: expected_result
        )
        result = intercom_frontend.add_binary_search_request(yara_rule)
        assert result is not None

        task_listener = InterComBackEndBinarySearchTask()
        task = task_listener.get_next_task()
        assert task == (yara_rule, None), 'task not correct'

        result = intercom_frontend.get_binary_search_result(result)
        assert result == (expected_result, task)

    def test_logs_task(self, intercom_frontend, monkeypatch):
        with NamedTemporaryFile() as tmp_file:
            expected_result = 'test\nlog'
            Path(tmp_file.name).write_text(expected_result)
            monkeypatch.setattr('intercom.back_end_binding.config.backend.logging.file_backend', tmp_file.name)
            with ThreadPoolExecutor(max_workers=2) as pool:
                task_listener = InterComBackEndLogsTask()
                result_future = pool.submit(intercom_frontend.get_backend_logs)
                sleep(0.2)  # give the task some time to reach the listener
                task_future = pool.submit(task_listener.get_next_task)
                task = task_future.result()
                result = result_future.result()
            assert task is None, 'task not correct'
            assert result == expected_result.split()
