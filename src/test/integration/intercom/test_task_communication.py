# pylint: disable=no-self-use
# pylint: disable=wrong-import-order

import gc
import os

import pytest

from intercom.back_end_binding import (
    InterComBackEndAnalysisPlugInsPublisher, InterComBackEndAnalysisTask, InterComBackEndCompareTask,
    InterComBackEndPeekBinaryTask, InterComBackEndRawDownloadTask, InterComBackEndReAnalyzeTask,
    InterComBackEndSingleFileTask, InterComBackEndTarRepackTask
)
from intercom.front_end_binding import InterComFrontEndBinding
from storage.binary_service import BinaryService
from test.common_helper import create_test_firmware


class AnalysisServiceMock:

    def __init__(self, config=None):
        pass

    def get_plugin_dict(self):
        return {'dummy': 'dummy description'}


@pytest.fixture
def intercom_frontend(cfg_tuple):
    _, configparser_cfg = cfg_tuple
    frontend = InterComFrontEndBinding(config=configparser_cfg)
    yield frontend

    frontend.redis.redis.flushdb()
    gc.collect()


@pytest.fixture
def test_fw():
    yield create_test_firmware()


@pytest.mark.cfg_defaults(
    {
        'expert-settings': {
            'communication-timeout': '1',
        },
    }
)
@pytest.mark.usefixtures('patch_cfg')
class TestInterComTaskCommunication:
    def test_analysis_task(self, intercom_frontend, test_fw, cfg_tuple):
        _, configparser_cfg = cfg_tuple
        backend = InterComBackEndAnalysisTask(config=configparser_cfg)

        intercom_frontend.add_analysis_task(test_fw)
        task = backend.get_next_task()
        assert task.uid == test_fw.uid, 'uid not correct'
        assert task.file_path is not None, 'file_path not set'
        assert os.path.exists(task.file_path), 'file does not exist'

    def test_single_file_task(self, intercom_frontend, test_fw, cfg_tuple):
        _, configparser_cfg = cfg_tuple
        backend = InterComBackEndSingleFileTask(config=configparser_cfg)
        test_fw.file_path = None
        test_fw.scheduled_analysis = ['binwalk']
        intercom_frontend.add_single_file_task(test_fw)
        task = backend.get_next_task()

        assert task.uid == test_fw.uid, 'uid not transported correctly'
        assert task.scheduled_analysis

    @pytest.mark.skip('TODO')
    def test_re_analyze_task(self, intercom_frontend, test_fw, cfg_tuple):
        _, configparser_cfg = cfg_tuple
        backend = InterComBackEndReAnalyzeTask(config=configparser_cfg)
        test_fw.file_path = None
        test_fw.binary = None
        intercom_frontend.add_re_analyze_task(test_fw)
        task = backend.get_next_task()
        assert task.uid == test_fw.uid, 'uid not correct'

    def test_compare_task(self, intercom_frontend, cfg_tuple):
        _, configparser_cfg = cfg_tuple
        backend = InterComBackEndCompareTask(config=configparser_cfg)
        intercom_frontend.add_compare_task('valid_id', force=False)
        result = backend.get_next_task()
        assert result == ('valid_id', False)

    def test_analysis_plugin_publication(self, intercom_frontend, cfg_tuple):
        _, configparser_cfg = cfg_tuple
        backend = InterComBackEndAnalysisPlugInsPublisher(config=configparser_cfg, analysis_service=AnalysisServiceMock())
        plugins = intercom_frontend.get_available_analysis_plugins()
        assert len(plugins) == 1, 'Not all plug-ins found'
        assert plugins == {'dummy': 'dummy description'}, 'content not correct'

    def test_analysis_plugin_publication_not_available(self, intercom_frontend):
        with pytest.raises(Exception):
            intercom_frontend.get_available_analysis_plugins()

    @pytest.mark.skip('TODO')
    def test_raw_download_task(self, monkeypatch, intercom_frontend, cfg_tuple):
        _, configparser_cfg = cfg_tuple
        bs = BinaryService(configparser_cfg)
        monkeypatch.setattr(bs, 'get_binary_and_file_name', lambda *_: (b'test', 'test.txt'))
        # does not work since generate_task_id is imported
        monkeypatch.setattr(intercom_frontend, 'generate_task_id', lambda *_: 'valid_uid_0.0')

        result = intercom_frontend.get_binary_and_filename('valid_uid')
        assert result is None, 'should be none because of timeout'

        backend = InterComBackEndRawDownloadTask(config=configparser_cfg)
        task = backend.get_next_task()
        assert task == 'valid_uid', 'task not correct'
        result = intercom_frontend.get_binary_and_filename('valid_uid_0.0')
        assert result == (b'test', 'test.txt'), 'retrieved binary not correct'

    @pytest.mark.skip('TODO')
    def test_peek_binary_task(self, monkeypatch, intercom_frontend, cfg_tuple):
        _, configparser_cfg = cfg_tuple
        bs = BinaryService(configparser_cfg)
        monkeypatch.setattr(bs, 'read_partial_binary', lambda *_: b'foobar')
        # does not work since generate_task_id is imported
        monkeypatch.setattr('intercom.front_end_binding.generate_task_id', lambda *_: 'valid_uid_0.0')

        result = intercom_frontend.peek_in_binary('valid_uid', 0, 512)
        assert result is None, 'should be none because of timeout'

        backend = InterComBackEndPeekBinaryTask(config=configparser_cfg)
        task = backend.get_next_task()
        assert task == ('valid_uid', 0, 512), 'task not correct'
        result = intercom_frontend.peek_in_binary('valid_uid', 0, 512)
        assert result == b'foobar', 'retrieved binary not correct'

    @pytest.mark.skip('TODO')
    def test_tar_repack_task(self, monkeypatch, intercom_frontend, cfg_tuple):
        _, configparser_cfg = cfg_tuple
        bs = BinaryService(configparser_cfg)
        monkeypatch.setattr(bs, 'get_repacked_binary_and_file_name', lambda *_: (b'test', 'test.tar'))
        # does not work since generate_task_id is imported
        monkeypatch.setattr('intercom.front_end_binding.generate_task_id', lambda *_: 'valid_uid_0.0')

        result = intercom_frontend.get_repacked_binary_and_file_name('valid_uid')
        assert result is None, 'should be none because of timeout'

        backend = InterComBackEndTarRepackTask(config=configparser_cfg)
        task = backend.get_next_task()
        assert task == 'valid_uid', 'task not correct'
        result = intercom_frontend.get_repacked_binary_and_file_name('valid_uid_0.0')
        assert result == (b'test', 'test.tar'), 'retrieved binary not correct'
