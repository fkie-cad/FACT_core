from ipaddress import ip_address

from fact.analysis.PluginBase import AnalysisBasePlugin
from fact.helperFunctions.compare_sets import substring_is_in_list

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


class AnalysisPlugin(AnalysisBasePlugin):
    NAME = 'interesting_uris'
    DEPENDENCIES = ['ip_and_uri_finder']  # noqa: RUF012
    MIME_WHITELIST = [  # noqa: RUF012
        'text/plain',
        'application/octet-stream',
        'application/x-executable',
        'application/x-object',
        'application/x-sharedlib',
        'application/x-dosexec',
    ]
    DESCRIPTION = (
        'This plugin filters all URIs identified inside the file based on relevance.'
        'The resulting list of URIs has a higher probability of representing important resources.'
    )
    VERSION = '0.1'
    FILE = __file__

    def process_object(self, file_object):
        list_of_ips_and_uris = file_object.processed_analysis['ip_and_uri_finder']['summary']
        uris_dict = self.remove_ip_v4_v6_addresses(list_of_ips_and_uris)
        blacklisted = self.blacklist_ip_and_uris(BLACKLIST, uris_dict)
        whitelisted = self.whitelist_ip_and_uris(WHITELIST, blacklisted)
        file_object.processed_analysis[self.NAME] = {'whitelisted': whitelisted, 'summary': whitelisted}
        return file_object

    @staticmethod
    def blacklist_ip_and_uris(blacklist: list, ip_and_uri_list: list) -> list:
        for ip_uri in ip_and_uri_list[:]:
            if substring_is_in_list(ip_uri.lower(), blacklist):
                ip_and_uri_list.remove(ip_uri)
        return ip_and_uri_list

    @staticmethod
    def whitelist_ip_and_uris(whitelist: list, ip_and_uri_list: list) -> list:
        clean_api_and_uri_list = []
        for ip_uri in set(ip_and_uri_list):
            if substring_is_in_list(ip_uri.lower(), whitelist):
                clean_api_and_uri_list.append(ip_uri)
        return clean_api_and_uri_list

    @staticmethod
    def is_valid_ip_address(ip: str) -> bool:
        try:
            ip_address(ip)
            return True
        except ValueError:
            return False

    def remove_ip_v4_v6_addresses(self, ip_and_uri_list: list) -> list:
        for ip_uri in ip_and_uri_list[:]:
            if self.is_valid_ip_address(ip_uri):
                ip_and_uri_list.remove(ip_uri)
        return ip_and_uri_list
