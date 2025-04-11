from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from multiprocessing import Manager
from pathlib import Path
from tempfile import NamedTemporaryFile
from time import sleep

import pytest

from intercom.back_end_binding import (
    InterComBackEndAnalysisTask,
    InterComBackEndBinarySearchTask,
    InterComBackEndCancelTask,
    InterComBackEndCheckYaraRuleTask,
    InterComBackEndCompareTask,
    InterComBackEndFileDiffTask,
    InterComBackEndLogsTask,
    InterComBackEndPeekBinaryTask,
    InterComBackEndRawDownloadTask,
    InterComBackEndReAnalyzeTask,
    InterComBackEndSingleFileTask,
    InterComBackEndTarRepackTask,
)
from intercom.common_redis_binding import publish_available_analysis_plugins
from intercom.front_end_binding import InterComFrontEndBinding
from test.common_helper import create_test_firmware
from test.mock import mock_patch


class AnalysisServiceMock:
    @staticmethod
    def get_plugin_dict():
        return {'dummy': 'dummy description'}


@pytest.fixture
def intercom_frontend():
    _intercom_frontend = InterComFrontEndBinding()
    yield _intercom_frontend
    _intercom_frontend.redis.redis.flushdb()


class FSOrganizerMock:
    @staticmethod
    def get_file_from_uid(uid: str) -> bytes:
        if uid == 'uid1':
            return b'binary content 1'
        if uid == 'uid2':
            return b'binary content 2'
        raise AssertionError('if this line reached something went wrong')


class MockDb:
    @staticmethod
    def get_file_name(uid: str) -> str:
        if uid == 'uid1':
            return 'file_name_1'
        if uid == 'uid2':
            return 'file_name_2'
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
        with Manager() as manager:
            analysis_finished_event = manager.Event()
            with mock_patch(manager, 'Event', lambda: analysis_finished_event):
                task_listener = InterComBackEndSingleFileTask(manager=manager)
                test_fw = create_test_firmware()
                test_fw.file_path = None
                test_fw.scheduled_analysis = ['binwalk']
                intercom_frontend.add_single_file_task(test_fw)
                task = task_listener.get_next_task()
                sleep(0.01)
                analysis_finished_event.set()

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
        plugin_dict = {'test_plugin': ('test plugin description', True, {}, '1.0.0', [], [], [], 2)}
        publish_available_analysis_plugins(plugin_dict)
        plugins = intercom_frontend.get_available_analysis_plugins()
        assert len(plugins) == 1, 'Not all plug-ins found'
        assert plugins == plugin_dict, 'content not correct'

    def test_analysis_plugin_publication_not_available(self, intercom_frontend):
        with pytest.raises(RuntimeError):
            intercom_frontend.get_available_analysis_plugins()

    def test_raw_download_task(self, monkeypatch, intercom_frontend):
        monkeypatch.setattr('intercom.back_end_binding.FSOrganizer.get_file_from_uid', lambda *_: b'test')
        monkeypatch.setattr('intercom.front_end_binding.generate_task_id', lambda *_: 'valid_uid_0.0')

        result = intercom_frontend.get_file_contents('valid_uid')
        assert result is None, 'should be none because of timeout'

        task_listener = InterComBackEndRawDownloadTask()
        task = task_listener.get_next_task()
        assert task == 'valid_uid', 'task not correct'
        result = intercom_frontend.get_file_contents('valid_uid_0.0')
        assert result == b'test', 'retrieved binary not correct'

    def test_file_diff_task(self, monkeypatch, intercom_frontend):
        monkeypatch.setattr('intercom.front_end_binding.generate_task_id', lambda _: 'valid_uid_0.0')
        monkeypatch.setattr('intercom.back_end_binding.FSOrganizer', FSOrganizerMock)

        result = intercom_frontend.get_file_diff(('uid1', 'uid2'))
        assert result is None, 'should be None because of timeout'

        task_listener = InterComBackEndFileDiffTask(db_interface=MockDb())
        task = task_listener.get_next_task()
        assert task == ('uid1', 'uid2'), 'task not correct'
        result = intercom_frontend.get_file_diff(('uid1', 'uid2'))
        expected_diff = '--- file_name_1\n+++ file_name_2\n@@ -1 +1 @@\n-binary content 1+binary content 2'
        assert result == expected_diff, 'file diff not correct'

    def test_peek_binary_task(self, monkeypatch, intercom_frontend):
        monkeypatch.setattr('intercom.back_end_binding.FSOrganizer.get_partial_file', lambda *_: b'foobar')
        monkeypatch.setattr('intercom.front_end_binding.generate_task_id', lambda *_: 'valid_uid_0.0')

        result = intercom_frontend.peek_in_binary('valid_uid', 0, 512)
        assert result is None, 'should be none because of timeout'

        task_listener = InterComBackEndPeekBinaryTask()
        task = task_listener.get_next_task()
        assert task == ('valid_uid', 0, 512), 'task not correct'
        result = intercom_frontend.peek_in_binary('valid_uid', 0, 512)
        assert result == b'foobar', 'retrieved binary not correct'

    def test_tar_repack_task(self, intercom_frontend, monkeypatch):
        monkeypatch.setattr('intercom.back_end_binding.FSOrganizer.get_repacked_file', lambda *_: b'test')
        monkeypatch.setattr('intercom.front_end_binding.generate_task_id', lambda *_: 'valid_uid_0.0')

        result = intercom_frontend.get_repacked_file('valid_uid')
        assert result is None, 'should be none because of timeout'

        task_listener = InterComBackEndTarRepackTask()
        task = task_listener.get_next_task()
        assert task == 'valid_uid', 'task not correct'
        result = intercom_frontend.get_repacked_file('valid_uid_0.0')
        assert result == b'test', 'retrieved binary not correct'

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

    def test_cancel_task(self, intercom_frontend):
        task = InterComBackEndCancelTask()
        root_uid = 'root_uid'
        intercom_frontend.cancel_analysis(root_uid)
        result = task.get_next_task()
        assert result == root_uid

    def test_get_yara_error(self, intercom_frontend):
        listener = InterComBackEndCheckYaraRuleTask()
        invalid_rule = 'rule foobar {}'
        intercom_frontend.get_yara_error(invalid_rule)
        task = listener.get_next_task()
        assert task == invalid_rule
        error = listener.get_response(task)
        assert 'expecting <condition>' in error

    def test_get_yara_error_valid(self, intercom_frontend):
        listener = InterComBackEndCheckYaraRuleTask()
        valid_rule = 'rule valid {condition: true}'
        error = listener.get_response(valid_rule)
        assert error == '', 'the rule should be valid and the error should be None'
