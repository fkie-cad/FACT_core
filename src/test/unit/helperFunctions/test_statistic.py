import pytest

from helperFunctions.statistic import calculate_total_files, is_sanitized_entry


@pytest.mark.parametrize('input_data, expected', [
    ([], 0),
    ([[('a', 1)], [('b', 2)]], 3),
    ([[('a', 1)], []], 1)
])
def test_calculate_total_files(input_data, expected):
    assert calculate_total_files(input_data) == expected


@pytest.mark.parametrize('input_data, expected', [
    ('crypto_material_summary_81abfc7a79c8c1ed85f6b9fc2c5d9a3edc4456c4aecb9f95b4d7a2bf9bf652da_76415', True),
    ('foobar', False),
])
def test_is_sanitized_entry(input_data, expected):
    assert is_sanitized_entry(input_data) == expected
