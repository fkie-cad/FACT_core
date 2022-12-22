import sys
from pathlib import Path

import pytest

try:
    from ..internal.helper_functions import (
        escape_special_characters,
        get_field_names,
        get_field_string,
        replace_characters_and_wildcards,
    )
except ImportError:
    sys.path.append(str(Path(__file__).parent.parent / 'internal'))
    from helper_functions import (
        escape_special_characters,
        get_field_names,
        get_field_string,
        replace_characters_and_wildcards,
    )


DB_FIELDS = [('cpe_id', 'TEXT'), ('year', 'INTEGER'), ('vendor', 'TEXT')]


def test_analyse_attribute():
    assert escape_special_characters('micr*osof?t_corp') == 'micr\\*osof\\?t_corp'


@pytest.mark.parametrize(
    'bound_string, unbound_string',
    [
        (
            ['a', 'micr*osof?t_corp', '*wind§ows 10*', '10.2.4', 'beta\\)1.2', 'sp1', '?en?', '-', '*', '*', '*'],
            [
                'a',
                'micr\\*osof\\?t_corp',
                '*wind\\§ows 10*',
                '10\\.2\\.4',
                'beta\\)1\\.2',
                'sp1',
                '?en?',
                'N/A',
                'ANY',
                'ANY',
                'ANY',
            ],
        ),
        (['10.2.4'], ['10\\.2\\.4']),
    ],
)
def test_replace_characters(bound_string, unbound_string):
    assert replace_characters_and_wildcards(bound_string) == unbound_string


def test_get_field_string():
    assert get_field_string(DB_FIELDS) == 'cpe_id TEXT NOT NULL, year INTEGER NOT NULL, vendor TEXT NOT NULL'


def test_get_field_names():
    assert get_field_names(DB_FIELDS) == 'cpe_id, year, vendor'
