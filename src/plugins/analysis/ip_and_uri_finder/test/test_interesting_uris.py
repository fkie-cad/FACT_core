import pytest

from ..internal.interesting_uris import (
    blacklist_ip_and_uris,
    find_interesting_uris,
    remove_ip_v4_v6_addresses,
    whitelist_ip_and_uris,
)


@pytest.mark.parametrize(
    ('input_list', 'blacklist', 'expected_output'),
    [
        ([], ['abc', 'def'], []),
        (['abcd', 'bcde'], [], ['abcd', 'bcde']),
        (['abcd', 'bcde', 'cdef', 'efgh'], ['abc', 'def'], ['bcde', 'efgh']),
        (['abcdefgh'], ['abc', 'def'], []),
    ],
)
def test_blacklist_ip_and_uris(input_list, blacklist, expected_output):
    assert blacklist_ip_and_uris(blacklist, input_list) == expected_output


@pytest.mark.parametrize(
    ('input_list', 'whitelist', 'expected_output'),
    [
        ([], ['abc', 'def'], []),
        (['abcd', 'bcde'], [], []),
        (['abcd', 'bcde', 'cdef', 'efgh'], ['abcd', 'cdef'], ['abcd', 'cdef']),
        (['abcf', 'bcfg', 'abci', 'bdhi'], ['abc', 'hi'], ['abcf', 'abci', 'bdhi']),
        (['abcdefgh'], ['abc', 'def'], ['abcdefgh']),
    ],
)
def test_white_ip_and_uris(input_list, whitelist, expected_output):
    assert sorted(whitelist_ip_and_uris(whitelist, input_list)) == expected_output


def test_find_interesting_uris():
    list_of_ips_and_uris = ['1.2.3.4', 'www.example.com', 'www.interesting.receive.org']
    assert find_interesting_uris(list_of_ips_and_uris) == ['www.interesting.receive.org']


@pytest.mark.backend_config_overwrite(
    {
        'plugin': {
            'ip_and_uri_finder': {
                'name': 'ip_and_uri_finder',
                'interesting_uri_blacklist': ['foo'],
                'interesting_uri_whitelist': ['bar'],
            },
        }
    },
)
def test_find_interesting_uris_with_custom_filters():
    list_of_ips_and_uris = ['www.foo.com', 'www.foo.bar.org', 'www.bar.io']
    assert find_interesting_uris(list_of_ips_and_uris) == ['www.bar.io']


@pytest.mark.backend_config_overwrite(
    {
        'plugin': {
            'ip_and_uri_finder': {
                'name': 'ip_and_uri_finder',
                'interesting_uri_blacklist': [],
                'interesting_uri_whitelist': [],
            },
        }
    },
)
def test_find_interesting_uris_with_empty_filters():
    list_of_ips_and_uris = ['www.example.com', 'www.foo.bar']
    assert sorted(find_interesting_uris(list_of_ips_and_uris)) == list_of_ips_and_uris


def test_remove_ip_v4_v6_addresses():
    assert remove_ip_v4_v6_addresses(['2001:db8::1', '127.0.255.250']) == []
    assert remove_ip_v4_v6_addresses(['abcd', '127.0.255.250', 'bcde']) == ['abcd', 'bcde']
    assert remove_ip_v4_v6_addresses(['abcd', '2001:db8::1', 'efgh']) == ['abcd', 'efgh']
