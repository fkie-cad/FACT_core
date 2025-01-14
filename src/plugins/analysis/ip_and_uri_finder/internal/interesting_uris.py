from __future__ import annotations

from ipaddress import ip_address

from helperFunctions.compare_sets import substring_is_in_list

WHITELIST = [
    'get',
    'set',
    'post',
    'send',
    'receive',
    'firmware',
    'router',
    'purenetworks.com',
    'tplinkwifi.net',
    'tplinklogin.net',
]

BLACKLIST = [
    'dict',
    'example',
    'lighttpd',
    'adobe',
    'netscape',
    'w3',
    'haxx.se',
    'any.org',
    'schemas',
    'openvpn',
    'gnu',
    'openssl',
    'support',
    'itunes',
    'github',
    'git',
    'google',
    'openwrt',
    'wikipedia',
    'wiki',
    'foo',
    'jquery.com',
    'showme.com',
    'blog',
    'forum',
    'documentation',
    'docs',
    'purl',
    'readme',
]


def find_interesting_uris(list_of_ips_and_uris: list[str]) -> list[str]:
    uris_dict = remove_ip_v4_v6_addresses(list_of_ips_and_uris)
    blacklisted = blacklist_ip_and_uris(BLACKLIST, uris_dict)
    return whitelist_ip_and_uris(WHITELIST, blacklisted)


def blacklist_ip_and_uris(blacklist: list[str], ip_and_uri_list: list[str]) -> list[str]:
    for ip_uri in ip_and_uri_list[:]:
        if substring_is_in_list(ip_uri.lower(), blacklist):
            ip_and_uri_list.remove(ip_uri)
    return ip_and_uri_list


def whitelist_ip_and_uris(whitelist: list[str], ip_and_uri_list: list[str]) -> list[str]:
    clean_api_and_uri_list = []
    for ip_uri in set(ip_and_uri_list):
        if substring_is_in_list(ip_uri.lower(), whitelist):
            clean_api_and_uri_list.append(ip_uri)
    return clean_api_and_uri_list


def is_valid_ip_address(ip: str) -> bool:
    try:
        ip_address(ip)
        return True
    except ValueError:
        return False


def remove_ip_v4_v6_addresses(ip_and_uri_list: list[str]) -> list[str]:
    for ip_uri in ip_and_uri_list[:]:
        if is_valid_ip_address(ip_uri):
            ip_and_uri_list.remove(ip_uri)
    return ip_and_uri_list
