# pylint: disable=use-implicit-booleaness-not-comparison
import logging
from multiprocessing import Manager
from time import time

import pytest

from objects.file import FileObject
from objects.firmware import Firmware
from scheduler.analysis_status import RECENTLY_FINISHED_DISPLAY_TIME_IN_SEC, AnalysisStatus


class TestAnalysisStatus:
    @classmethod
    def setup_class(cls):
        cls.status = AnalysisStatus()
        cls.manager = Manager()
        cls.status.currently_running_lock = cls.manager.Lock()  # pylint: disable=no-member

    @classmethod
    def teardown_class(cls):
        cls.status.shutdown()
        cls.manager.shutdown()

    def test_add_firmware_to_current_analyses(self):
        self.status.currently_running = {}
        fw = Firmware(binary=b'foo')
        fw.files_included = ['foo', 'bar']
        self.status.add_to_current_analyses(fw)
        assert fw.uid in self.status.currently_running
        result = self.status.currently_running[fw.uid]
        assert result['files_to_unpack'] == ['foo', 'bar']
        assert result['files_to_analyze'] == [fw.uid]
        assert result['unpacked_files_count'] == 1
        assert result['analyzed_files_count'] == 0
        assert result['total_files_count'] == 3

    def test_add_file_to_current_analyses(self):
        self.status.currently_running = {
            'parent_uid': {
                'files_to_unpack': ['foo'],
                'files_to_analyze': ['bar'],
                'total_files_count': 2,
                'unpacked_files_count': 1,
            }
        }
        fo = FileObject(binary=b'foo')
        fo.root_uid = 'parent_uid'
        fo.files_included = ['bar', 'new']
        fo.uid = 'foo'
        self.status.add_to_current_analyses(fo)

        result = self.status.currently_running['parent_uid']
        assert sorted(result['files_to_unpack']) == ['new']
        assert sorted(result['files_to_analyze']) == ['bar', 'foo']
        assert result['unpacked_files_count'] == 2
        assert result['total_files_count'] == 3

    def test_add_duplicate_file_to_current_analyses(self):
        self.status.currently_running = {
            'parent_uid': {
                'files_to_unpack': ['foo'],
                'files_to_analyze': ['duplicate'],
                'total_files_count': 2,
                'unpacked_files_count': 3,
            }
        }
        fo = FileObject(binary=b'foo')
        fo.root_uid = 'parent_uid'
        fo.files_included = ['duplicate']
        fo.uid = 'foo'
        self.status.add_to_current_analyses(fo)
        assert sorted(self.status.currently_running['parent_uid']['files_to_unpack']) == []
        assert sorted(self.status.currently_running['parent_uid']['files_to_analyze']) == ['duplicate', 'foo']
        assert self.status.currently_running['parent_uid']['total_files_count'] == 2

    def test_remove_partial_from_current_analyses(self):
        self.status.currently_running = {
            'parent_uid': {'files_to_unpack': [], 'files_to_analyze': ['foo', 'bar'], 'analyzed_files_count': 0}
        }
        fo = FileObject(binary=b'foo')
        fo.root_uid = 'parent_uid'
        fo.uid = 'foo'
        self.status.remove_from_current_analyses(fo)
        assert 'parent_uid' in self.status.currently_running
        assert self.status.currently_running['parent_uid']['files_to_analyze'] == ['bar']
        assert self.status.currently_running['parent_uid']['analyzed_files_count'] == 1

    def test_remove_but_not_found(self, caplog):
        self.status.currently_running = {'parent_uid': {'files_to_analyze': ['bar'], 'analyzed_files_count': 1}}
        fo = FileObject(binary=b'foo')
        fo.root_uid = 'parent_uid'
        fo.uid = 'foo'
        with caplog.at_level(logging.DEBUG):
            self.status.remove_from_current_analyses(fo)
            assert any('Failed to remove' in m for m in caplog.messages)

    def test_remove_fully_from_current_analyses(self):
        self.status.currently_running = {
            'parent_uid': {
                'files_to_unpack': [],
                'files_to_analyze': ['foo'],
                'analyzed_files_count': 1,
                'start_time': 0,
                'total_files_count': 2,
                'hid': 'FooBar 1.0',
            }
        }
        self.status.recently_finished = {}
        fo = FileObject(binary=b'foo')
        fo.root_uid = 'parent_uid'
        fo.uid = 'foo'
        self.status.remove_from_current_analyses(fo)
        assert self.status.currently_running == {}
        assert 'parent_uid' in self.status.recently_finished
        assert self.status.recently_finished['parent_uid']['total_files_count'] == 2

    def test_remove_but_still_unpacking(self):
        self.status.currently_running = {
            'parent_uid': {'files_to_unpack': ['bar'], 'files_to_analyze': ['foo'], 'analyzed_files_count': 1}
        }
        fo = FileObject(binary=b'foo')
        fo.root_uid = 'parent_uid'
        fo.uid = 'foo'
        self.status.remove_from_current_analyses(fo)
        result = self.status.currently_running
        assert 'parent_uid' in result
        assert result['parent_uid']['files_to_analyze'] == []
        assert result['parent_uid']['files_to_unpack'] == ['bar']
        assert result['parent_uid']['analyzed_files_count'] == 2

    @pytest.mark.parametrize(
        'time_finished_delay, expected_result', [(0, True), (RECENTLY_FINISHED_DISPLAY_TIME_IN_SEC + 1, False)]
    )
    def test_clear_recently_finished(self, time_finished_delay, expected_result):
        self.status.recently_finished = {'foo': {'time_finished': time() - time_finished_delay}}
        self.status.clear_recently_finished()
        assert bool('foo' in self.status.recently_finished) == expected_result
