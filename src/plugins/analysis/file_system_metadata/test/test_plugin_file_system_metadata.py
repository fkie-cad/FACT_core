from __future__ import annotations

from base64 import b64encode
from io import FileIO
from pathlib import Path

import pytest

from analysis.plugin import AnalysisFailedError

from ..code.file_system_metadata import (
    SGID_BIT,
    STICKY_BIT,
    SUID_BIT,
    AnalysisPlugin,
    FileMetadata,
    _extract_metadata_from_tar,
    _file_mode_contains_bit,
    _get_results_for_tar_file,
    _tag_should_be_set,
)

TEST_DATA_DIR = Path(__file__).parent / 'data'
EXPECTED_FILE_COUNT = 5

UNYAFFS_MOCK_OUTPUT = """
Header check OK, chunk size = 2K, spare size = 64, no bad block info.
crw-rw--w-   5,   0 2014-07-19 01:28 dev/tty
-rw-r--r--       38 2014-07-19 01:31 build
drwxr-xr-x        0 2016-10-11 03:12 sbin
lrwxrwxrwx        0 2014-07-19 01:28 sbin/ifconfig -> ../bin/busybox
-rwsr-xr-x  1906904 2014-07-19 03:18 bin/busybox
-rwxr-xr-x   278544 2014-07-19 01:27 bin/agent
-rw-r--r--     2252 2014-07-19 01:19 www/images/delete.png
"""


class TarMock:
    mode = 0
    uname = ''
    gname = ''
    uid = 0
    gid = 0
    mtime = 0

    def __init__(self, name):
        self.name = name


class MockFileTypeResult:
    def __init__(self, mime):
        self.mime = mime


def _file_results_to_dict(results: list[FileMetadata]) -> dict[str, FileMetadata]:
    return {metadata.key: metadata for metadata in results}


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
class TestFileSystemMetadata:
    test_file_tar = TEST_DATA_DIR / 'test.tar'
    test_file_fs = TEST_DATA_DIR / 'squashfs.img'

    @pytest.mark.flaky(reruns=2)  # test may fail once on a new system
    def test_extract_metadata_from_file_system(self, analysis_plugin):
        metadata = analysis_plugin._extract_metadata_from_file_system(FileIO(self.test_file_fs))
        assert len(metadata) == EXPECTED_FILE_COUNT
        result = _file_results_to_dict(metadata)

        testfile_sticky_key = _b64_encode('testfile_sticky')
        testfile_sgid_key = _b64_encode('testfile_sgid')
        testfile_suid_key = _b64_encode('testfile_suid')
        testfile_all_key = _b64_encode('testfile_all')
        testfile_none_key = _b64_encode('testfile_none')

        assert all(
            key in result
            for key in [testfile_sticky_key, testfile_sgid_key, testfile_suid_key, testfile_all_key, testfile_none_key]
        )

        assert result[testfile_sticky_key].mode == '101777'
        assert result[testfile_sgid_key].mode == '102777'
        assert result[testfile_suid_key].mode == '104777'
        assert result[testfile_all_key].mode == '107777'
        assert result[testfile_none_key].mode == '100777'

        assert result[testfile_sticky_key].sticky_bit is True
        assert result[testfile_sgid_key].sgid_bit is True
        assert result[testfile_suid_key].suid_bit is True
        assert result[testfile_all_key].sticky_bit is True
        assert result[testfile_all_key].sgid_bit is True
        assert result[testfile_all_key].suid_bit is True
        assert result[testfile_none_key].sticky_bit is False
        assert result[testfile_none_key].sgid_bit is False
        assert result[testfile_none_key].suid_bit is False

        assert result[testfile_sticky_key].name == 'testfile_sticky'
        assert result[testfile_sticky_key].user == 'root'
        assert result[testfile_sticky_key].group == 'root'
        assert result[testfile_sticky_key].uid == 0
        assert result[testfile_sticky_key].gid == 0
        assert result[testfile_sticky_key].modification_time == 1518167842.0

    def test_extract_metadata_from_file_system__unmountable(self, analysis_plugin):
        with pytest.raises(AnalysisFailedError, match='Mounting the file system failed'):
            analysis_plugin._extract_metadata_from_file_system(FileIO(self.test_file_tar))

    def test_extract_metadata_from_tar(self):
        metadata = _extract_metadata_from_tar(FileIO(self.test_file_tar))
        assert len(metadata) == EXPECTED_FILE_COUNT
        result = _file_results_to_dict(metadata)

        testfile_sticky_key = _b64_encode('mount/testfile_sticky')
        testfile_sgid_key = _b64_encode('mount/testfile_sgid')
        testfile_suid_key = _b64_encode('mount/testfile_suid')
        testfile_all_key = _b64_encode('mount/testfile_all')
        testfile_none_key = _b64_encode('mount/testfile_none')

        assert all(
            key in result
            for key in [testfile_sticky_key, testfile_sgid_key, testfile_suid_key, testfile_all_key, testfile_none_key]
        )

        assert result[testfile_sticky_key].mode == '1777'
        assert result[testfile_sgid_key].mode == '2777'
        assert result[testfile_suid_key].mode == '4777'
        assert result[testfile_all_key].mode == '7777'
        assert result[testfile_none_key].mode == '777'

        assert result[testfile_sticky_key].sticky_bit is True
        assert result[testfile_sgid_key].sgid_bit is True
        assert result[testfile_suid_key].suid_bit is True
        assert result[testfile_all_key].sticky_bit is True
        assert result[testfile_all_key].sgid_bit is True
        assert result[testfile_all_key].suid_bit is True
        assert result[testfile_none_key].sticky_bit is False
        assert result[testfile_none_key].sgid_bit is False
        assert result[testfile_none_key].suid_bit is False

        assert result[testfile_sticky_key].name == 'testfile_sticky'
        assert result[testfile_sticky_key].user == 'root'
        assert result[testfile_sticky_key].group == 'root'
        assert result[testfile_sticky_key].uid == 0
        assert result[testfile_sticky_key].gid == 0
        assert result[testfile_sticky_key].modification_time == 1518167842

    def test_extract_metadata_from_tar_gz(self):
        metadata = _extract_metadata_from_tar(FileIO(TEST_DATA_DIR / 'test.tar.gz'))
        assert len(metadata) == EXPECTED_FILE_COUNT
        result = _file_results_to_dict(metadata)
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

    def test_extract_metadata_from_tar__packed_tar_bz(self):
        metadata = _extract_metadata_from_tar(FileIO(TEST_DATA_DIR / 'test.tar.bz2'))
        assert len(metadata) == EXPECTED_FILE_COUNT
        result = _file_results_to_dict(metadata)
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

    def test_extract_metadata_tar_unreadable(self):
        with pytest.raises(RuntimeError):
            _extract_metadata_from_tar(FileIO(TEST_DATA_DIR / 'squashfs.img'))

    def test_extract_metadata_from_tar__eof_error(self):
        result = _extract_metadata_from_tar(FileIO(TEST_DATA_DIR / 'broken.tar.gz'))
        assert 0 < len(result) < 5, 'Some files should be found but not all'

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
    def test_get_extended_file_permissions(self, mode, expected):
        result = [_file_mode_contains_bit(mode, bit) for bit in (SUID_BIT, SGID_BIT, STICKY_BIT)]
        assert result == expected

    def test_analyze(self, analysis_plugin):
        result = analysis_plugin.analyze(
            FileIO(self.test_file_fs), {}, {'file_type': MockFileTypeResult('filesystem/squashfs')}
        )
        assert result is not None
        assert isinstance(result, analysis_plugin.Schema)
        assert len(result.files) == EXPECTED_FILE_COUNT
        metadata = _file_results_to_dict(result.files)
        assert _b64_encode('testfile_sticky') in metadata

    def test_analyze_wrong_mime(self, analysis_plugin):
        result = analysis_plugin.analyze(FileIO(self.test_file_fs), {}, {'file_type': MockFileTypeResult('wrong_mime')})
        assert result is not None
        assert isinstance(result, analysis_plugin.Schema)
        assert result.files == []

    def test_enter_tar_results_malformed_path(self, analysis_plugin):
        file_name = './foo/bar'
        metadata = _get_results_for_tar_file(TarMock(file_name))
        assert metadata.key == _b64_encode('foo/bar')

    def test_tag_should_be_set(self, analysis_plugin):
        def _get_results(user, suid, sgid):
            return analysis_plugin.Schema(
                files=[
                    FileMetadata(
                        mode='',
                        mode_human_readable='',
                        name='',
                        path='',
                        user=user,
                        uid=0,
                        group='',
                        gid=0,
                        modification_time=0.0,
                        suid_bit=suid,
                        sgid_bit=sgid,
                        sticky_bit=False,
                        key='',
                    )
                ]
            )

        test_data = [
            (_get_results(user='root', suid=True, sgid=True), True),
            (_get_results(user='root', suid=True, sgid=False), True),
            (_get_results(user='root', suid=False, sgid=True), True),
            (_get_results(user='root', suid=False, sgid=False), False),
            (_get_results(user='user', suid=True, sgid=True), False),
            (_get_results(user='user', suid=True, sgid=False), False),
            (_get_results(user='user', suid=False, sgid=True), False),
            (_get_results(user='user', suid=False, sgid=False), False),
        ]
        for input_data, expected_result in test_data:
            assert _tag_should_be_set(input_data) == expected_result

    def test_yaffs(self, analysis_plugin):
        analysis = {
            'file_type': MockFileTypeResult('filesystem/yaffs'),
            'unpacker': {
                'plugin_used': 'YAFFS',
                'output': UNYAFFS_MOCK_OUTPUT,
            },
        }
        result = analysis_plugin.analyze(FileIO(self.test_file_fs), {}, analysis)
        assert isinstance(result, analysis_plugin.Schema)
        assert len(result.files) == 5
        file_results = {r.name: r for r in result.files}
        assert 'busybox' in file_results
        assert file_results['busybox'].path == '/bin/busybox'
        assert file_results['busybox'].suid_bit is True
        assert file_results['ifconfig'].path == '/sbin/ifconfig'


def _b64_encode(string):
    return b64encode(string.encode()).decode()
