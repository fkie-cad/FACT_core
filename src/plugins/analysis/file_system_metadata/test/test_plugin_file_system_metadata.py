from __future__ import annotations

from base64 import b64encode
from pathlib import Path

import pytest
from flaky import flaky

from test.common_helper import TEST_FW, TEST_FW_2, CommonDatabaseMock

from ..code.file_system_metadata import AnalysisPlugin, FsKeys, SUID_BIT, SGID_BIT, STICKY_BIT

PLUGIN_NAME = 'file_system_metadata'
TEST_DATA_DIR = Path(__file__).parent / 'data'


class FoMock:
    def __init__(self, file_path: Path | None, file_type: str | None, parent_fo_type=''):
        self.file_path = file_path
        self.processed_analysis = {'file_type': {'result': {'mime': file_type}}, PLUGIN_NAME: {}}
        self.file_name = 'test'
        self.binary = file_path.read_bytes() if file_path is not None else None
        self.uid = 'deadbeef_123'
        self.root_uid = 'root_uid'
        self.parents = []
        if parent_fo_type:
            self.temporary_data = {'parent_fo_type': parent_fo_type}

    def get_root_uid(self):
        return 'foo'


class TarMock:
    mode = 0
    uname = ''
    gname = ''
    uid = 0
    gid = 0
    mtime = 0

    def __init__(self, name):
        self.name = name


class DbMock(CommonDatabaseMock):
    FILE_TYPE_RESULTS = {  # noqa: RUF012
        TEST_FW.uid: {'result': {'mime': 'application/octet-stream'}},
        TEST_FW_2.uid: {'result': {'mime': 'filesystem/cramfs'}},
    }

    def get_analysis(self, uid, _):
        return self.FILE_TYPE_RESULTS[uid]


@pytest.fixture
def fs_metadata_plugin(analysis_plugin):
    analysis_plugin.result = {}
    analysis_plugin.db = DbMock()
    return analysis_plugin


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
class TestFileSystemMetadata:
    test_file_tar = TEST_DATA_DIR / 'test.tar'
    test_file_fs = TEST_DATA_DIR / 'squashfs.img'

    def test_extract_metadata__correct_method_is_called(self, fs_metadata_plugin, monkeypatch):
        result = None

        def _extract_metadata_from_archive_mock(_):
            nonlocal result
            result = 'archive'

        monkeypatch.setattr(fs_metadata_plugin, '_extract_metadata_from_tar', _extract_metadata_from_archive_mock)
        fo = FoMock(None, 'application/x-tar')
        fs_metadata_plugin._extract_metadata(fo)
        assert result == 'archive'

        monkeypatch.undo()

        def _extract_metadata_from_file_system_mock(_):
            nonlocal result
            result = 'fs'

        monkeypatch.setattr(
            fs_metadata_plugin, '_extract_metadata_from_file_system', _extract_metadata_from_file_system_mock
        )
        fo = FoMock(None, 'filesystem/ext4')
        fs_metadata_plugin._extract_metadata(fo)
        assert result == 'fs'

    @flaky(max_runs=2, min_passes=1)  # test may fail once on a new system
    def test_extract_metadata_from_file_system(self, fs_metadata_plugin):
        fo = FoMock(self.test_file_fs, 'filesystem/squashfs')
        result = fs_metadata_plugin._extract_metadata_from_file_system(fo)['files']

        testfile_sticky_key = _b64_encode('testfile_sticky')
        testfile_sgid_key = _b64_encode('testfile_sgid')
        testfile_suid_key = _b64_encode('testfile_suid')
        testfile_all_key = _b64_encode('testfile_all')
        testfile_none_key = _b64_encode('testfile_none')

        assert all(
            key in result
            for key in [testfile_sticky_key, testfile_sgid_key, testfile_suid_key, testfile_all_key, testfile_none_key]
        )

        assert result[testfile_sticky_key][FsKeys.MODE] == '1777'
        assert result[testfile_sgid_key][FsKeys.MODE] == '2777'
        assert result[testfile_suid_key][FsKeys.MODE] == '4777'
        assert result[testfile_all_key][FsKeys.MODE] == '7777'
        assert result[testfile_none_key][FsKeys.MODE] == '777'

        assert result[testfile_sticky_key][FsKeys.STICKY] is True
        assert result[testfile_sgid_key][FsKeys.SGID] is True
        assert result[testfile_suid_key][FsKeys.SUID] is True
        assert result[testfile_all_key][FsKeys.STICKY] is True
        assert result[testfile_all_key][FsKeys.SGID] is True
        assert result[testfile_all_key][FsKeys.SUID] is True
        assert result[testfile_none_key][FsKeys.STICKY] is False
        assert result[testfile_none_key][FsKeys.SGID] is False
        assert result[testfile_none_key][FsKeys.SUID] is False

        assert result[testfile_sticky_key][FsKeys.NAME] == 'testfile_sticky'
        assert result[testfile_sticky_key][FsKeys.USER] == 'root'
        assert result[testfile_sticky_key][FsKeys.GROUP] == 'root'
        assert result[testfile_sticky_key][FsKeys.UID] == 0
        assert result[testfile_sticky_key][FsKeys.GID] == 0
        assert result[testfile_sticky_key][FsKeys.M_TIME] == 1518167842.0  # noqa: PLR2004

    def test_extract_metadata_from_file_system__unmountable(self, fs_metadata_plugin):
        fo = FoMock(self.test_file_tar, 'application/x-tar')
        result = fs_metadata_plugin._extract_metadata_from_file_system(fo)

        assert 'failed' in result
        assert 'files' not in result

    def test_extract_metadata_from_tar(self, fs_metadata_plugin):
        fo = FoMock(self.test_file_tar, 'application/x-tar')
        result = fs_metadata_plugin._extract_metadata_from_tar(fo)['files']

        testfile_sticky_key = _b64_encode('mount/testfile_sticky')
        testfile_sgid_key = _b64_encode('mount/testfile_sgid')
        testfile_suid_key = _b64_encode('mount/testfile_suid')
        testfile_all_key = _b64_encode('mount/testfile_all')
        testfile_none_key = _b64_encode('mount/testfile_none')

        assert all(
            key in result
            for key in [testfile_sticky_key, testfile_sgid_key, testfile_suid_key, testfile_all_key, testfile_none_key]
        )

        assert result[testfile_sticky_key][FsKeys.MODE] == '1777'
        assert result[testfile_sgid_key][FsKeys.MODE] == '2777'
        assert result[testfile_suid_key][FsKeys.MODE] == '4777'
        assert result[testfile_all_key][FsKeys.MODE] == '7777'
        assert result[testfile_none_key][FsKeys.MODE] == '777'

        assert result[testfile_sticky_key][FsKeys.STICKY] is True
        assert result[testfile_sgid_key][FsKeys.SGID] is True
        assert result[testfile_suid_key][FsKeys.SUID] is True
        assert result[testfile_all_key][FsKeys.STICKY] is True
        assert result[testfile_all_key][FsKeys.SGID] is True
        assert result[testfile_all_key][FsKeys.SUID] is True
        assert result[testfile_none_key][FsKeys.STICKY] is False
        assert result[testfile_none_key][FsKeys.SGID] is False
        assert result[testfile_none_key][FsKeys.SUID] is False

        assert result[testfile_sticky_key][FsKeys.NAME] == 'testfile_sticky'
        assert result[testfile_sticky_key][FsKeys.USER] == 'root'
        assert result[testfile_sticky_key][FsKeys.GROUP] == 'root'
        assert result[testfile_sticky_key][FsKeys.UID] == 0
        assert result[testfile_sticky_key][FsKeys.GID] == 0
        assert result[testfile_sticky_key][FsKeys.M_TIME] == 1518167842  # noqa: PLR2004

    def test_extract_metadata_from_tar__packed_tar_gz(self, fs_metadata_plugin):
        test_file_tar_gz = TEST_DATA_DIR / 'test.tar.gz'
        fo = FoMock(test_file_tar_gz, 'application/gzip')
        result = fs_metadata_plugin._extract_metadata_from_tar(fo)['files']
        assert all(
            _b64_encode(key) in result
            for key in [
                'mount/testfile_sticky',
                'mount/testfile_sgid',
                'mount/testfile_suid',
                'mount/testfile_all',
                'mount/testfile_none',
            ]
        )

    def test_extract_metadata_from_tar__packed_tar_bz(self, fs_metadata_plugin):
        test_file_tar_bz = TEST_DATA_DIR / 'test.tar.bz2'
        fo = FoMock(test_file_tar_bz, 'application/x-bzip2')
        result = fs_metadata_plugin._extract_metadata_from_tar(fo)['files']
        assert all(
            _b64_encode(key) in result
            for key in [
                'mount/testfile_sticky',
                'mount/testfile_sgid',
                'mount/testfile_suid',
                'mount/testfile_all',
                'mount/testfile_none',
            ]
        )

    def test_extract_metadata_from_tar__tar_unreadable(self, fs_metadata_plugin):
        test_file = TEST_DATA_DIR / 'squashfs.img'
        fo = FoMock(test_file, 'application/gzip')
        result = fs_metadata_plugin._extract_metadata_from_tar(fo)
        assert result == {}

    def test_extract_metadata_from_tar__eof_error(self, fs_metadata_plugin):
        test_file_tar_gz = TEST_DATA_DIR / 'broken.tar.gz'
        fo = FoMock(test_file_tar_gz, 'application/gzip')
        result = fs_metadata_plugin._extract_metadata_from_tar(fo)
        assert 0 < len(result) < 5  # noqa: PLR2004

    @pytest.mark.parametrize(
        ('mode', 'expected'),
        [
            ('777', [False, False, False]),
            ('0777', [False, False, False]),
            ('1777', [False, False, True]),
            ('2777', [False, True, False]),
            ('3777', [False, True, True]),
            ('4777', [True, False, False]),
            ('5777', [True, False, True]),
            ('6777', [True, True, False]),
            ('7777', [True, True, True]),
            ('00007777', [True, True, True]),
        ],
    )
    def test_get_extended_file_permissions(self, fs_metadata_plugin, mode, expected):
        result = [fs_metadata_plugin._file_mode_contains_bit(mode, bit) for bit in (SUID_BIT, SGID_BIT, STICKY_BIT)]
        assert result == expected

    def test_parent_has_file_system_metadata(self, fs_metadata_plugin):
        # fo has temporary_data entry
        fo = FoMock(None, None, parent_fo_type='wrong_type')
        assert fs_metadata_plugin._parent_has_file_system_metadata(fo) is False
        fo = FoMock(None, None, parent_fo_type='filesystem/ext2')
        assert fs_metadata_plugin._parent_has_file_system_metadata(fo) is True

    def test_no_temporary_data(self, fs_metadata_plugin):
        fo = FoMock(None, None)

        fo.parents = [TEST_FW.uid]
        # mime-type in mocked db is 'application/octet-stream' so the result should be false
        assert fs_metadata_plugin._parent_has_file_system_metadata(fo) is False

        fo.parents = [TEST_FW_2.uid]
        # mime-type in mocked db is 'filesystem/cramfs' so the result should be true
        assert fs_metadata_plugin._parent_has_file_system_metadata(fo) is True

    def test_process_object(self, fs_metadata_plugin):
        fo = FoMock(self.test_file_fs, 'filesystem/squashfs')
        result = fs_metadata_plugin.process_object(fo)
        assert 'file_system_metadata' in result.processed_analysis
        assert 'contained_in_file_system' in result.processed_analysis['file_system_metadata']
        assert result.processed_analysis['file_system_metadata']['contained_in_file_system'] is False
        assert result.processed_analysis['file_system_metadata'] != {}
        assert 'files' in result.processed_analysis['file_system_metadata']
        assert _b64_encode('testfile_sticky') in result.processed_analysis['file_system_metadata']['files']

        fo_2 = FoMock(self.test_file_fs, 'wrong_mime', parent_fo_type='filesystem/ext4')
        result = fs_metadata_plugin.process_object(fo_2)
        assert 'file_system_metadata' in result.processed_analysis
        assert 'contained_in_file_system' in result.processed_analysis['file_system_metadata']

        fo_3 = FoMock(self.test_file_fs, 'wrong_mime')
        result = fs_metadata_plugin.process_object(fo_3)
        assert 'file_system_metadata' in result.processed_analysis
        assert result.processed_analysis['file_system_metadata']['contained_in_file_system'] is False
        assert len(result.processed_analysis['file_system_metadata'].keys()) == 1

    def test_enter_results_for_tar_file__malformed_path(self, fs_metadata_plugin):
        file_name = './foo/bar'
        result = fs_metadata_plugin._get_results_for_tar_file(TarMock(file_name))
        assert result != {}
        assert _b64_encode(file_name) not in result
        assert _b64_encode('foo/bar') in result

    def test_tag_should_be_set(self, fs_metadata_plugin):
        def _get_results(user, suid, sgid):
            return {'foo': {FsKeys.USER: user, FsKeys.SUID: suid, FsKeys.SGID: sgid}}

        test_data = [
            (_get_results(user='root', suid=True, sgid=True), True),
            (_get_results(user='root', suid=True, sgid=False), True),
            (_get_results(user='root', suid=False, sgid=True), True),
            (_get_results(user='root', suid=False, sgid=False), False),
            (_get_results(user='user', suid=True, sgid=True), False),
            (_get_results(user='user', suid=True, sgid=False), False),
            (_get_results(user='user', suid=False, sgid=True), False),
            (_get_results(user='user', suid=False, sgid=False), False),
            ({'foo': {FsKeys.SUID: True, FsKeys.SGID: True}}, False),  # user missing (legacy: was not always set)
        ]
        for input_data, expected_result in test_data:
            assert fs_metadata_plugin._tag_should_be_set(input_data) == expected_result


def _b64_encode(string):
    return b64encode(string.encode()).decode()
