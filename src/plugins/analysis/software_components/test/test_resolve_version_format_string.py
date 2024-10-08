from pathlib import Path

import pytest

from ..internal.resolve_version_format_string import (
    extract_data_from_ghidra,
    filter_implausible_results,
)


@pytest.mark.parametrize(
    ('test_file', 'input_data', 'expected_output'),
    [
        (
            'format_string_arm-linux-gnueabihf',
            {'mode': 'format_string', 'key_string_list': ['get_version v%s']},
            ['1.2.3'],
        ),
        (
            'fake-liblzma',
            {'mode': 'version_function', 'function_name': 'lzma_version_string'},
            ['5.2.1'],
        ),
    ],
)
def test_extract_data_from_ghidra(backend_config, test_file, input_data, expected_output):
    test_file = Path(__file__).parent / 'data' / test_file
    result = extract_data_from_ghidra(test_file.read_bytes(), input_data, str(backend_config.docker_mount_base_dir))
    assert len(result) == 1
    assert result == expected_output


@pytest.mark.parametrize(
    ('test_input', 'expected_output'),
    [
        ([], []),
        (['1.2.3.4', 'foobar'], ['1.2.3.4']),
        (['v1.2-r1234'], ['v1.2-r1234']),
    ],
)
def test_filter_implausible_results(test_input, expected_output):
    assert filter_implausible_results(test_input) == expected_output
