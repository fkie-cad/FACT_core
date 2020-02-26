from pathlib import Path

from ..internal.resolve_version_format_string import extract_data_from_ghidra


def test_extract_data_from_ghidra():
    key_string = 'get_version v%s'
    test_file = Path(__file__).parent / 'data' / 'get_version_arm-linux-gnueabihf'
    result = extract_data_from_ghidra(test_file.read_bytes(), [key_string])
    assert len(result) == 1
    assert result == ['1.2.3']
