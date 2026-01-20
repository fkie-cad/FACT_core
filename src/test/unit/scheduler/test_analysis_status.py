import logging
from time import time

import pytest

from objects.file import FileObject
from objects.firmware import Firmware
from scheduler.analysis_status import RECENTLY_FINISHED_DISPLAY_TIME_IN_SEC, AnalysisStatus, FwAnalysisStatus

ROOT_UID = 'root_uid'


class MockRedis:
    def __init__(self):
        self.analysis_status = None

    def set_analysis_status(self, status):
        self.analysis_status = status


class TestAnalysisStatus:
    def setup_method(self):
        self.status = AnalysisStatus()
        self.status._worker.redis = MockRedis()

    def test_init_firmware(self):
        fw = Firmware(binary=b'foo')
        fw.files_included = ['foo', 'bar']
        self.status.init_firmware(fw)
        self.status._worker._update_status()

        assert fw.uid in self.status._worker.currently_running
        result = self.status._worker.currently_running[fw.uid]
        assert result.files_to_unpack == {fw.uid}
        assert result.files_to_analyze == {fw.uid}
        assert result.completed_files == set()
        assert result.unpacked_files_count == 0
        assert result.analyzed_files_count == 0
        assert result.total_files_count == 1

        # after unpacking, the file is added again with add_object to add the included files
        self.status.add_object(fw)
        self.status._worker._update_status()

        assert fw.uid in self.status._worker.currently_running
        result = self.status._worker.currently_running[fw.uid]
        assert result.files_to_unpack == {'foo', 'bar'}
        assert result.files_to_analyze == {fw.uid}
        assert result.completed_files == set()
        assert result.unpacked_files_count == 1
        assert result.analyzed_files_count == 0
        assert result.total_files_count == 3

    def test_add_file_to_current_analyses(self):
        self.status._worker.currently_running = {
            ROOT_UID: FwAnalysisStatus(
                analysis_plugins={},
                files_to_analyze={'bar'},
                files_to_unpack={'foo'},
                hid='',
                total_files_count=2,
                total_files_with_duplicates=2,
                unpacked_files_count=1,
            )
        }
        fo = FileObject(binary=b'foo')
        fo.root_uid = ROOT_UID
        fo.files_included = ['bar', 'new']
        fo.uid = 'foo'
        self.status.add_object(fo)
        self.status._worker._update_status()

        result = self.status._worker.currently_running[ROOT_UID]
        assert sorted(result.files_to_unpack) == ['new']
        assert sorted(result.files_to_analyze) == ['bar', 'foo']
        assert result.unpacked_files_count == 2
        assert result.total_files_count == 3
        assert result.total_files_with_duplicates == 3

    def test_add_duplicate_file_to_current_analyses(self):
        self.status._worker.currently_running = {
            ROOT_UID: FwAnalysisStatus(
                files_to_unpack={'foo'},
                files_to_analyze={'duplicate'},
                total_files_count=2,
                unpacked_files_count=3,
                total_files_with_duplicates=2,
                analysis_plugins={},
                hid='',
            )
        }
        fo = FileObject(binary=b'foo')
        fo.root_uid = ROOT_UID
        fo.files_included = ['duplicate']
        fo.uid = 'foo'
        self.status.add_object(fo)
        self.status._worker._update_status()

        result = self.status._worker.currently_running[ROOT_UID]
        assert sorted(result.files_to_unpack) == []
        assert sorted(result.files_to_analyze) == ['duplicate', 'foo']
        assert result.total_files_count == 2

    def test_remove_partial_from_current_analyses(self):
        self.status._worker.currently_running = {
            ROOT_UID: FwAnalysisStatus(
                files_to_unpack=set(),
                files_to_analyze={'foo', 'bar'},
                analysis_plugins={},
                hid='',
                total_files_count=3,
            )
        }
        fo = FileObject(binary=b'foo')
        fo.root_uid = ROOT_UID
        fo.uid = 'foo'
        self.status.remove_object(fo)
        self.status._worker._update_status()

        assert ROOT_UID in self.status._worker.currently_running
        assert self.status._worker.currently_running[ROOT_UID].files_to_analyze == {'bar'}
        assert self.status._worker.currently_running[ROOT_UID].analyzed_files_count == 1

    def test_remove_but_not_found(self, caplog):
        self.status._worker.currently_running = {
            ROOT_UID: FwAnalysisStatus(
                files_to_unpack=set(),
                analyzed_files_count=1,
                files_to_analyze={'bar'},
                analysis_plugins={},
                hid='',
                total_files_count=3,
            )
        }
        fo = FileObject(binary=b'foo')
        fo.root_uid = ROOT_UID
        fo.uid = 'foo'
        with caplog.at_level(logging.DEBUG):
            self.status.remove_object(fo)
            self.status._worker._update_status()
            assert any('Failed to remove' in m for m in caplog.messages)

    def test_remove_fully_from_current_analyses(self):
        self.status._worker.currently_running = {
            ROOT_UID: FwAnalysisStatus(
                files_to_unpack=set(),
                files_to_analyze={'foo'},
                analyzed_files_count=1,
                analysis_plugins={},
                hid='',
                total_files_count=2,
            )
        }
        self.status.recently_finished = {}
        fo = FileObject(binary=b'foo')
        fo.root_uid = ROOT_UID
        fo.uid = 'foo'
        self.status.remove_object(fo)
        self.status._worker._update_status()

        assert self.status._worker.currently_running == {}
        assert ROOT_UID in self.status._worker.recently_finished
        assert self.status._worker.recently_finished[ROOT_UID]['total_files_count'] == 2

    def test_remove_but_still_unpacking(self):
        self.status._worker.currently_running = {
            ROOT_UID: FwAnalysisStatus(
                files_to_unpack={'bar'},
                files_to_analyze={'foo'},
                analyzed_files_count=1,
                analysis_plugins={},
                hid='',
                total_files_count=3,
            )
        }
        fo = FileObject(binary=b'foo')
        fo.root_uid = ROOT_UID
        fo.uid = 'foo'
        self.status.remove_object(fo)
        self.status._worker._update_status()

        result = self.status._worker.currently_running
        assert ROOT_UID in result
        assert result[ROOT_UID].files_to_analyze == set()
        assert result[ROOT_UID].files_to_unpack == {'bar'}
        assert result[ROOT_UID].analyzed_files_count == 2

    @pytest.mark.parametrize(
        ('time_finished_delay', 'expected_result'), [(0, True), (RECENTLY_FINISHED_DISPLAY_TIME_IN_SEC + 1, False)]
    )
    def test_clear_recently_finished(self, time_finished_delay, expected_result):
        self.status._worker.recently_finished = {'foo': {'time_finished': time() - time_finished_delay}}
        self.status._worker._clear_recently_finished()
        assert bool('foo' in self.status._worker.recently_finished) == expected_result

    def test_cancel_analysis(self):
        self.status._worker.currently_running = {
            ROOT_UID: FwAnalysisStatus(
                files_to_unpack=set(),
                files_to_analyze={'foo'},
                analysis_plugins={},
                hid='',
                total_files_count=3,
            )
        }
        self.status._currently_analyzed[ROOT_UID] = True
        fo = FileObject(binary=b'foo')
        fo.root_uid = ROOT_UID
        fo.uid = 'foo'
        assert self.status.fw_analysis_is_in_progress(fo)

        self.status.cancel_analysis(ROOT_UID)
        self.status._worker._update_status()

        assert ROOT_UID not in self.status._worker.currently_running
        assert ROOT_UID not in self.status._currently_analyzed
        assert not self.status.fw_analysis_is_in_progress(fo)

    def test_cancel_unknown_uid(self):
        self.status._worker.currently_running = {
            ROOT_UID: FwAnalysisStatus(
                files_to_unpack=set(),
                files_to_analyze={'foo'},
                analysis_plugins={},
                hid='',
                total_files_count=3,
            )
        }
        self.status.cancel_analysis('unknown')
        self.status._worker._update_status()

        assert ROOT_UID in self.status._worker.currently_running

    def test_add_update(self):
        fw = Firmware(binary=b'foo')
        fw.files_included = ['foo', 'bar']
        self.status.add_update(fw, fw.files_included)
        # _update_status is called twice, because add_object is called first and then add_update
        self.status._worker._update_status()
        self.status._worker._update_status()

        assert fw.uid in self.status._worker.currently_running
        result = self.status._worker.currently_running[fw.uid]
        assert result.files_to_unpack == set()
        assert result.completed_files == set()
        assert result.unpacked_files_count == result.total_files_count
        assert result.analyzed_files_count == 0
        assert result.files_to_analyze == {fw.uid, *fw.files_included}
        assert result.total_files_count == len(fw.files_included) + 1

    def test_add_analysis(self):
        self.status._worker.currently_running = {
            ROOT_UID: FwAnalysisStatus(
                files_to_unpack=set(),
                files_to_analyze={'foo', 'bar'},
                analysis_plugins={},
                hid='',
                total_files_count=3,
            )
        }
        self.status._currently_analyzed[ROOT_UID] = True
        fo = FileObject(binary=b'foo')
        fo.root_uid = ROOT_UID
        fo.uid = 'foo'

        result = self.status._worker.currently_running[ROOT_UID]
        assert result.analysis_plugins == {}

        self.status.add_analysis(fo, 'some_plugin')
        self.status._worker._update_status()

        assert result.analysis_plugins == {'some_plugin': 1}

    def test_store_status(self):
        self.status._worker.currently_running = {
            ROOT_UID: FwAnalysisStatus(
                files_to_unpack={'bar'},
                files_to_analyze={'foo', 'bar'},
                analysis_plugins={},
                hid='',
                unpacked_files_count=2,
                total_files_count=3,
            )
        }
        recently_finished = {
            'other_UID': {
                'duration': 13.37,
                'total_files_count': 1337,
                'time_finished': 1337,
                'hid': 'analysis_status.hid',
            }
        }
        self.status._worker.recently_finished = recently_finished
        self.status._worker._store_status()

        status = self.status._worker.redis.analysis_status
        assert ROOT_UID in status['current_analyses']
        assert status['current_analyses'][ROOT_UID]['unpacked_count'] == 2
        assert status['current_analyses'][ROOT_UID]['analyzed_count'] == 0
        assert status['current_analyses'][ROOT_UID]['total_count'] == 3
        assert status['recently_canceled_analyses'] == {}
        assert status['recently_finished_analyses'] == recently_finished
