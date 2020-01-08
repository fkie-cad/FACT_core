from internal.helper_functions import unbinding, analyse_attribute

BOUND_LIST = ['a', 'micr*osof?t_corp', '*wind§ows 10*', '10.2.4', 'beta\\)1.2', 'sp1', '?en?', '-', '*', '*', '*']
BOUND_VERSION = ['10.2.4']
UNBOUND_VERSION = ['10\\.2\\.4']
UNBOUND_LIST = ['a', 'micr\\*osof\\?t_corp', '*wind\\§ows 10*', '10\\.2\\.4', 'beta\\)1\\.2', 'sp1', '?en?', 'NA',
                'ANY', 'ANY', 'ANY']


def test_analyse_attribute():
    assert analyse_attribute('micr*osof?t_corp') == 'micr\\*osof\\?t_corp'


def test_unbinding():
    assert UNBOUND_LIST == unbinding(BOUND_LIST)
    assert UNBOUND_VERSION == unbinding(BOUND_VERSION)
