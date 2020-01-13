import sys
from pathlib import Path

import pytest

try:
    from internal.helper_functions import unbind, escape_special_characters
except ImportError:
    sys.path.append(str(Path(__file__).parent.parent / 'internal'))
    from helper_functions import unbind, escape_special_characters


def test_analyse_attribute():
    assert escape_special_characters('micr*osof?t_corp') == 'micr\\*osof\\?t_corp'


@pytest.mark.parametrize('bound_string, unbound_string', [
    (
        ['a', 'micr*osof?t_corp', '*wind§ows 10*', '10.2.4', 'beta\\)1.2', 'sp1', '?en?', '-', '*', '*', '*'],
        ['a', 'micr\\*osof\\?t_corp', '*wind\\§ows 10*', '10\\.2\\.4', 'beta\\)1\\.2', 'sp1', '?en?', 'NA', 'ANY', 'ANY', 'ANY']
    ),
    (['10.2.4'], ['10\\.2\\.4'])
])
def test_unbind(bound_string, unbound_string):
    assert unbind(bound_string) == unbound_string
