
from ..internal.helper_functions import replace_characters_and_wildcards


def test_replace_characters_and_wildcards():
    attributes = ['a', '*', '-', 'b']
    expected_result = ['a', 'ANY', 'N/A', 'b']

    result = replace_characters_and_wildcards(attributes)

    assert result == expected_result
