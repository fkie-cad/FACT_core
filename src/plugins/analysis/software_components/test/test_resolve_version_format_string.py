from pathlib import Path

import pytest

from test.common_helper import create_docker_mount_base_dir

from ..internal.resolve_version_format_string import extract_data_from_ghidra, filter_implausible_results


def test_extract_data_from_ghidra():
    key_string = 'get_version v%s'
    test_file = Path(__file__).parent / 'data' / 'format_string_arm-linux-gnueabihf'
    docker_mount_base_dir = create_docker_mount_base_dir()
    result = extract_data_from_ghidra(test_file.read_bytes(), [key_string], str(docker_mount_base_dir))
    assert len(result) == 1
    assert result == ['1.2.3']


@pytest.mark.parametrize(
    'test_input, expected_output', [
        ([], []),
        (['1.2.3.4', 'foobar'], ['1.2.3.4']),
        (['v1.2-r1234'], ['v1.2-r1234']),
    ]
)
def test_filter_implausible_results(test_input, expected_output):
    assert filter_implausible_results(test_input) == expected_output
