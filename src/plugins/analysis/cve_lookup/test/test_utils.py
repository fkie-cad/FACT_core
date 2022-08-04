import sys
from pathlib import Path

import pytest

try:
    from ..internal.utils import replace_characters_and_wildcards
except ImportError:
    sys.path.append(str(Path(__file__).parent.parent / 'internal'))
    from utils import replace_characters_and_wildcards


@pytest.mark.parametrize('bound_string, unbound_string', [
    (
        ['a', 'micr*osof?t_corp', '*wind§ows 10*', '10.2.4', 'beta\\)1.2', 'sp1', '?en?', '-', '*', '*', '*'],
        ['a', 'micr\\*osof\\?t_corp', '*wind\\§ows 10*', '10\\.2\\.4', 'beta\\)1\\.2', 'sp1', '?en?', 'N/A', 'ANY', 'ANY', 'ANY']
    ),
    (['10.2.4'], ['10\\.2\\.4'])
])
def test_replace_characters_and_wildcards(bound_string, unbound_string):
    assert replace_characters_and_wildcards(bound_string) == unbound_string
