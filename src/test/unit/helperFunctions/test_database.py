import pytest

from helperFunctions.database import is_sanitized_entry


@pytest.mark.parametrize('input_data, expected', [
    ('crypto_material_summary_81abfc7a79c8c1ed85f6b9fc2c5d9a3edc4456c4aecb9f95b4d7a2bf9bf652da_76415', True),
    ('foobar', False),
])
def test_is_sanitized_entry(input_data, expected):
    assert is_sanitized_entry(input_data) == expected
