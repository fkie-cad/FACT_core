import pytest

from ..internal.helper_functions import replace_wildcards


@pytest.mark.parametrize(
    ('attributes', 'expected_result'),
    [
        (['*', 'attribute1', 'attribute2'], ['ANY', 'attribute1', 'attribute2']),
        (['attribute1', '-', 'attribute2'], ['attribute1', 'N/A', 'attribute2']),
        (['attribute1', 'attribute2'], ['attribute1', 'attribute2']),
    ],
)
def test_replace_wildcards(attributes, expected_result):
    assert replace_wildcards(attributes) == expected_result
