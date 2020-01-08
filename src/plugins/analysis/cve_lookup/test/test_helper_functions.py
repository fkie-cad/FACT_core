import sys
from pathlib import Path

try:
    from internal.helper_functions import unbind, escape_special_characters
except ImportError:
    sys.path.append(str(Path(__file__).parent.parent / 'internal'))
    from helper_functions import unbind, escape_special_characters

BOUND_LIST = ['a', 'micr*osof?t_corp', '*wind§ows 10*', '10.2.4', 'beta\\)1.2', 'sp1', '?en?', '-', '*', '*', '*']
BOUND_VERSION = ['10.2.4']
UNBOUND_VERSION = ['10\\.2\\.4']
UNBOUND_LIST = ['a', 'micr\\*osof\\?t_corp', '*wind\\§ows 10*', '10\\.2\\.4', 'beta\\)1\\.2', 'sp1', '?en?', 'NA',
                'ANY', 'ANY', 'ANY']


def test_analyse_attribute():
    assert escape_special_characters('micr*osof?t_corp') == 'micr\\*osof\\?t_corp'


def test_unbind():
    assert UNBOUND_LIST == unbind(BOUND_LIST)
    assert UNBOUND_VERSION == unbind(BOUND_VERSION)
