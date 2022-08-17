import pytest

from storage.entry_conversion import get_analysis_without_meta, sanitize


@pytest.mark.parametrize(
    'input_dict, expected',
    [
        ({}, {}),
        ({
            'a': 1, 'b': '2'
        }, {
            'a': 1, 'b': '2'
        }),
        ({
            'illegal': 'a\0b\0c'
        }, {
            'illegal': 'abc'
        }),
        ({
            'nested': {
                'key': 'a\0b\0c'
            }
        }, {
            'nested': {
                'key': 'abc'
            }
        }),
    ],
)
def test_sanitize(input_dict, expected):
    sanitize(input_dict)
    assert input_dict == expected


@pytest.mark.parametrize(
    'input_dict, expected', [
        ({}, {}),
        ({
            'a': 1
        }, {
            'a': 1
        }),
        ({
            'a': 1, 'summary': [], 'tags': {}
        }, {
            'a': 1
        }),
    ],
)
def test_get_analysis_without_meta(input_dict, expected):
    assert get_analysis_without_meta(input_dict) == expected
