# pylint: disable=protected-access,wrong-import-order
import logging
from time import time

import pytest

from objects.file import FileObject
from objects.firmware import Firmware
from scheduler.Analysis import RECENTLY_FINISHED_DISPLAY_TIME_IN_SEC
from test.unit.scheduler.test_analysis import UtilityBase


class TestCurrentAnalyses(UtilityBase):

    def test_add_firmware_to_current_analyses(self):
        self.scheduler.currently_running = {}
        fw = Firmware(binary=b'foo')
        fw.files_included = ['foo', 'bar']
        self.scheduler._add_to_current_analyses(fw)
        assert fw.uid in self.scheduler.currently_running
        result = self.scheduler.currently_running[fw.uid]
        assert result['files_to_unpack'] == ['foo', 'bar']
        assert result['files_to_analyze'] == [fw.uid]
        assert result['unpacked_files_count'] == 1
        assert result['analyzed_files_count'] == 0
        assert result['total_files_count'] == 3

    def test_add_file_to_current_analyses(self):
        self.scheduler.currently_running = {'parent_uid': {
            'files_to_unpack': ['foo'], 'files_to_analyze': ['bar'], 'total_files_count': 2, 'unpacked_files_count': 1
        }}
        fo = FileObject(binary=b'foo')
        fo.parent_firmware_uids = {'parent_uid'}
        fo.files_included = ['bar', 'new']
        fo.uid = 'foo'
        self.scheduler._add_to_current_analyses(fo)

        result = self.scheduler.currently_running['parent_uid']
        assert sorted(result['files_to_unpack']) == ['new']
        assert sorted(result['files_to_analyze']) == ['bar', 'foo']
        assert result['unpacked_files_count'] == 2
        assert result['total_files_count'] == 3

    def test_add_duplicate_file_to_current_analyses(self):
        self.scheduler.currently_running = {'parent_uid': {
            'files_to_unpack': ['foo'], 'files_to_analyze': ['duplicate'], 'total_files_count': 2, 'unpacked_files_count': 3
        }}
        fo = FileObject(binary=b'foo')
        fo.parent_firmware_uids = {'parent_uid'}
        fo.files_included = ['duplicate']
        fo.uid = 'foo'
        self.scheduler._add_to_current_analyses(fo)
        assert sorted(self.scheduler.currently_running['parent_uid']['files_to_unpack']) == []
        assert sorted(self.scheduler.currently_running['parent_uid']['files_to_analyze']) == ['duplicate', 'foo']
        assert self.scheduler.currently_running['parent_uid']['total_files_count'] == 2

    def test_remove_partial_from_current_analyses(self):
        self.scheduler.currently_running = {'parent_uid': {'files_to_unpack': [], 'files_to_analyze': ['foo', 'bar'], 'analyzed_files_count': 0}}
        fo = FileObject(binary=b'foo')
        fo.parent_firmware_uids = {'parent_uid'}
        fo.uid = 'foo'
        self.scheduler._remove_from_current_analyses(fo)
        assert 'parent_uid' in self.scheduler.currently_running
        assert self.scheduler.currently_running['parent_uid']['files_to_analyze'] == ['bar']
        assert self.scheduler.currently_running['parent_uid']['analyzed_files_count'] == 1

    def test_remove_but_not_found(self, caplog):
        self.scheduler.currently_running = {'parent_uid': {'files_to_analyze': ['bar'], 'analyzed_files_count': 1}}
        fo = FileObject(binary=b'foo')
        fo.parent_firmware_uids = {'parent_uid'}
        fo.uid = 'foo'
        with caplog.at_level(logging.WARNING):
            self.scheduler._remove_from_current_analyses(fo)
            assert any('but it is not included' in m for m in caplog.messages)

    def test_remove_fully_from_current_analyses(self):
        self.scheduler.currently_running = {'parent_uid': {
            'files_to_unpack': [], 'files_to_analyze': ['foo'], 'analyzed_files_count': 1, 'start_time': 0,
            'total_files_count': 2, 'hid': 'FooBar 1.0'
        }}
        self.scheduler.recently_finished = {}
        fo = FileObject(binary=b'foo')
        fo.parent_firmware_uids = {'parent_uid'}
        fo.uid = 'foo'
        self.scheduler._remove_from_current_analyses(fo)
        assert self.scheduler.currently_running == {}
        assert 'parent_uid' in self.scheduler.recently_finished
        assert self.scheduler.recently_finished['parent_uid']['total_files_count'] == 2

    def test_remove_but_still_unpacking(self):
        self.scheduler.currently_running = {'parent_uid': {'files_to_unpack': ['bar'], 'files_to_analyze': ['foo'], 'analyzed_files_count': 1}}
        fo = FileObject(binary=b'foo')
        fo.parent_firmware_uids = {'parent_uid'}
        fo.uid = 'foo'
        self.scheduler._remove_from_current_analyses(fo)
        result = self.scheduler.currently_running
        assert 'parent_uid' in result
        assert result['parent_uid']['files_to_analyze'] == []
        assert result['parent_uid']['files_to_unpack'] == ['bar']
        assert result['parent_uid']['analyzed_files_count'] == 2

    @pytest.mark.parametrize('time_finished_delay, expected_result', [
        (0, True),
        (RECENTLY_FINISHED_DISPLAY_TIME_IN_SEC + 1, False)
    ])
    def test_clear_recently_finished(self, time_finished_delay, expected_result):
        self.scheduler.recently_finished = {'foo': {'time_finished': time() - time_finished_delay}}
        self.scheduler._clear_recently_finished()
        assert bool('foo' in self.scheduler.recently_finished) == expected_result
