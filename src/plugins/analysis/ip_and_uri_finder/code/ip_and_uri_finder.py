from __future__ import annotations

import logging
from contextlib import suppress
from itertools import product
from pathlib import Path
from re import search
from typing import TYPE_CHECKING, List, Optional

import geoip2.database
from common_analysis_ip_and_uri_finder import CommonAnalysisIPAndURIFinder
from geoip2.errors import AddressNotFoundError
from maxminddb.errors import InvalidDatabaseError
from pydantic import BaseModel

from analysis.plugin import AnalysisPluginV0
from analysis.plugin.compat import AnalysisBasePluginAdapterMixin

if TYPE_CHECKING:
    from io import FileIO

GEOIP_DATABASE_PATH = Path(__file__).parent.parent / 'bin/GeoLite2-City/GeoLite2-City.mmdb'

IP_V4_BLACKLIST = [r'127.0.[0-9]+.1', r'255.[0-9]+.[0-9]+.[0-9]+']  # localhost  # subnet masks
IP_V6_BLACKLIST = [r'^[0-9A-Za-z]::$', r'^::[0-9A-Za-z]$', r'^[0-9A-Za-z]::[0-9A-Za-z]$', r'^::$']  # trivial addresses


class IpAddress(BaseModel):
    address: str
    location: Optional[Location]


class Location(BaseModel):
    longitude: float
    latitude: float


class AnalysisPlugin(AnalysisPluginV0, AnalysisBasePluginAdapterMixin):
    class Schema(BaseModel):
        ips_v4: List[IpAddress]
        ips_v6: List[IpAddress]
        uris: List[str]

    def __init__(self):
        self.ip_and_uri_finder = CommonAnalysisIPAndURIFinder()
        try:
            self.reader = geoip2.database.Reader(str(GEOIP_DATABASE_PATH))
        except FileNotFoundError:
            logging.error('could not load GeoIP database')
            self.reader = None

        super().__init__(
            metadata=self.MetaData(
                name='ip_and_uri_finder',
                description='Search file for IP addresses and URIs based on regular expressions.',
                version='1.0.0',
                Schema=self.Schema,
                mime_whitelist=[
                    'text/plain',
                    'application/octet-stream',
                    'application/x-executable',
                    'application/x-object',
                    'application/x-sharedlib',
                    'application/x-dosexec',
                ],
                system_version=self.ip_and_uri_finder.system_version,
            ),
        )

    def analyze(self, file_handle: FileIO, virtual_file_path: dict[str, list[str]], analyses: dict) -> Schema:
        del virtual_file_path, analyses
        ip_data = self.ip_and_uri_finder.analyze_file(file_handle.name, separate_ipv6=True)
        ip_v4_results = _remove_blacklisted(_remove_duplicates(ip_data['ips_v4']), IP_V4_BLACKLIST)
        ip_v6_results = _remove_blacklisted(_remove_duplicates(ip_data['ips_v6']), IP_V6_BLACKLIST)
        uris = _remove_duplicates(ip_data['uris'])
        return self.Schema(
            ips_v4=[IpAddress(address=ip, location=self.find_geo_location(ip)) for ip in ip_v4_results],
            ips_v6=[IpAddress(address=ip, location=self.find_geo_location(ip)) for ip in ip_v6_results],
            uris=uris,
        )

    def find_geo_location(self, ip_address: str) -> Location | None:
        if self.reader is None:
            return None
        try:
            response = self.reader.city(ip_address)
            return Location(
                longitude=float(response.location.longitude),
                latitude=float(response.location.latitude),
            )
        except (
            AttributeError,
            AddressNotFoundError,
            FileNotFoundError,
            ValueError,
            InvalidDatabaseError,
        ) as exception:
            logging.debug(f'Error during {self.NAME} analysis: {exception!s}', exc_info=True)
            return None

    def summarize(self, result: Schema) -> list:
        summary = [*result.uris]
        for ip_list in [result.ips_v4, result.ips_v6]:
            for ip in ip_list:
                summary.append(ip.address)
        return summary


def _remove_duplicates(input_list: list[str]) -> list[str]:
    return list(set(input_list))


def _remove_blacklisted(ip_list: list[str], blacklist: list[str]) -> list[str]:
    for ip, blacklist_entry in product(ip_list, blacklist):
        if search(blacklist_entry, ip):
            with suppress(ValueError):
                ip_list.remove(ip)
    return ip_list
