from ipaddress import ip_address, IPv4Address

from analysis.PluginBase import AnalysisBasePlugin

WHITELIST = ['get', 'set', 'post', 'send', 'receive', 'firmware', 'router', 'purenetworks.com', 'tplinkwifi.net',
                 'tplinklogin.net']

BLACKLIST = ['dict', 'example', 'lighttpd', 'adobe', 'netscape', 'w3', 'haxx.se', 'any.org',
                 'schemas', 'openvpn', 'gnu', 'openssl', 'support', 'itunes', 'github', 'git', 'google',
                 'openwrt', 'wikipedia', 'wiki', 'foo', 'jquery.com', 'showme.com', 'blog', 'forum', 'documentation',
                 'docs', 'purl', 'readme']


class AnalysisPlugin(AnalysisBasePlugin):
    '''
    This plug-in filters found IPs and URIs
    '''
    NAME = 'ip_and_uri_finder_filter'
    DEPENDENCIES = ['ip_and_uri_finder']
    MIME_BLACKLIST = []
    DESCRIPTION = 'Filters found IPs and URIs'
    VERSION = '0.1'

    def __init__(self, plugin_administrator, config=None, recursive=True, timeout=300):
        super().__init__(plugin_administrator, config=config, recursive=recursive, timeout=timeout, plugin_path=__file__)

    def process_object(self, file_object):
        list_of_ips_and_uris = file_object.processed_analysis['ip_and_uri_finder']['summary']
        uris_dict = self.remove_ip_v4_v6_addresses(list_of_ips_and_uris)
        blacklisted = self.blacklist_ip_and_uris(BLACKLIST, uris_dict)
        whitelisted = self.whitelist_ip_and_uris(WHITELIST, blacklisted)
        file_object.processed_analysis[self.NAME] = {"whitelisted": whitelisted, "summary": whitelisted}
        return file_object

    @staticmethod
    def blacklist_ip_and_uris(deny_list: list, ip_and_uri_list: list) -> list:
        for ip_uri in ip_and_uri_list:
            for entry in deny_list:
                if entry in ip_uri.lower():
                    ip_and_uri_list.remove(ip_uri)
        return ip_and_uri_list

    @staticmethod
    def whitelist_ip_and_uris(allow_list: list, ip_and_uri_list: list) -> list:
        clean_api_and_uri_list = []
        for ip_uri in ip_and_uri_list:
            for entry in allow_list:
                if entry in ip_uri.lower():
                    if ip_uri not in clean_api_and_uri_list:
                        clean_api_and_uri_list.append(ip_uri)
        return clean_api_and_uri_list

    @staticmethod
    def list_to_dict(lst: list) -> dict:
        res_dict = {lst[i]: lst[i + 1] for i in range(0, len(lst), 2)}
        return res_dict

    @staticmethod
    def valid_ip_address(ip: str) -> str:
        try:
            return "IPv4" if type(ip_address(ip)) is IPv4Address else "IPv6"
        except ValueError:
            return "0"

    def remove_ip_v4_v6_addresses(self, ip_and_uri_list: list) -> list:
        for ip_uri in ip_and_uri_list:
            if self.valid_ip_address(ip_uri) == 'IPv4' or self.valid_ip_address(ip_uri) == 'IPv6':
                ip_and_uri_list.remove(ip_uri)
        return ip_and_uri_list
