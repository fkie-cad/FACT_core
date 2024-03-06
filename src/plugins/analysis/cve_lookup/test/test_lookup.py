import pytest

from ..internal.lookup import Lookup


@pytest.mark.parametrize(
    ('software_name', 'expected_output'),
    [
        ('windows 7', ['windows', 'windows_7']),
        ('Linux Kernel', ['linux', 'linux_kernel', 'kernel']),
    ],
)
def test_generate_search_terms(software_name, expected_output):
    result = Lookup._generate_search_terms(software_name)
    assert result == expected_output
