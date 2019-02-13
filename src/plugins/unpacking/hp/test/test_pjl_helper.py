from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from common_helper_files import get_binary_from_file

from ..internal.pjl_helper import (
    _extract_file_from_upgrade, _get_binary_of_upgrade,
    _get_end_postion_of_first_preamble, _get_file_fingerprint,
    _get_name_of_upgrade, _get_size_of_upgrade, _get_type_and_value,
    _is_upgrade, get_pjl_commands
)

TEST_DATA_UPGRADE_RAW = (b'\x40\x50\x4A\x4C\x20\x55\x50\x47\x52\x41\x44\x45\x20\x53\x49\x5A\x45\x3D\x31\x31\x32\x0D\x0A'
                         b'\x03\x00\xA8\x01\x48\x50\x20\x43\x6F\x6C\x6F\x72\x20\x4C\x61\x73\x65\x72\x4A\x65\x74\x20\x43'
                         b'\x50\x34\x35\x32\x35\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20'
                         b'\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x30'
                         b'\x37\x32\x32\x30\x32\x20\x20\x04\x53\xB1\x21\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x54\x65\x73\x74\x20\x46\x69\x6C\x65\x20\x31\x0D\x0A')
TEST_COMMAND = {'raw': b'@PJL UPGRADE SIZE=112', 'begin_offset': 0, 'end_offset': 21, 'type': b'UPGRADE', 'value': b'SIZE=112'}


@pytest.mark.parametrize('input_data, payload', [
    (b'abcde...\x25\x2d12345X\x0ablah\x25\x2d12345X\x0ablub', b'blah'),
    (b'no_preamble', b'no_p')
])
def test_get_end_position_of_first_pjl(input_data, payload):
    end_position = _get_end_postion_of_first_preamble(input_data)
    assert input_data[end_position:end_position + 4] == payload


def test_get_pjl_commands():
    test_data = b'\x00\x00@PJL COMMENT test comment\0a not_part of pjl command or additional stuff@PJL JOB\0a'
    result = get_pjl_commands(test_data)
    assert len(result) == 2


@pytest.mark.parametrize('command, expected_type, expected_value', [
    (b'@PJL COMMENT test comment', b'COMMENT', b'test comment'),
    (b'@PJL JOB', b'JOB', None)
])
def test_get_type_and_value(command, expected_type, expected_value):
    pjl_type, pjl_value = _get_type_and_value(command)
    assert pjl_type == expected_type
    assert pjl_value == expected_value


def test_get_name_of_upgrade():
    assert _get_name_of_upgrade(TEST_DATA_UPGRADE_RAW, TEST_COMMAND) == 'HP Color LaserJet CP4525'


def test_pjl_command_is_upgrade():
    assert _is_upgrade(TEST_COMMAND)


def test_get_upgrade_size():
    assert _get_size_of_upgrade(TEST_COMMAND) == 112


def test_get_binary_of_upgrade():
    assert _get_binary_of_upgrade(TEST_DATA_UPGRADE_RAW, TEST_COMMAND, 'file_name') == b'\x00Test File 1'


@pytest.mark.parametrize('input_data, fingerprint', [
    (b'no finger print', None),
    (b'RANDOM_DATA--=</Begin HP Signed File Fingerprint\\>=-- The Fingerprint --=</End HP Signed File Fingerprint\\>=--SOME_MORE_RANDOM_DATA',
     b'--=</Begin HP Signed File Fingerprint\\>=-- The Fingerprint --=</End HP Signed File Fingerprint\\>=--')
])
def test_get_file_fingerprint(input_data, fingerprint):
    assert _get_file_fingerprint(input_data) == fingerprint


def test_extract_file_from_upgrade():
    with TemporaryDirectory(prefix='fact_test_') as tmp_dir:
        expected_path_of_dumped_file = Path(tmp_dir, 'HP_Color_LaserJet_CP4525.bin')

        _extract_file_from_upgrade(TEST_DATA_UPGRADE_RAW, TEST_COMMAND, tmp_dir)

        assert expected_path_of_dumped_file.exists()

        dumped_file_binary = get_binary_from_file(str(expected_path_of_dumped_file))
        assert dumped_file_binary == b'\x00Test File 1'
