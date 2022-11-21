import json
import sys
from datetime import datetime
from io import BytesIO
from pathlib import Path
from typing import List, Optional, Tuple
from xml.etree.ElementTree import ParseError, parse
from zipfile import BadZipFile, ZipFile

import requests
from requests.exceptions import RequestException
from retry import retry

try:
    from ..internal.helper_functions import CveEntry, CveLookupException, CveSummaryEntry
except (ImportError, SystemError):
    sys.path.append(str(Path(__file__).parent.parent / 'internal'))
    from helper_functions import CveEntry, CveLookupException, CveSummaryEntry

CPE_FILE = 'official-cpe-dictionary_v2.3.xml'
CPE_URL = f'https://nvd.nist.gov/feeds/xml/cpe/dictionary/{CPE_FILE}.zip'
CVE_URL = 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{}.json.zip'


def get_cve_links(url: str, selected_years: Optional[List[int]] = None) -> List[str]:
    if selected_years is None:
        selected_years = range(2002, datetime.today().year + 1)
    return [url.format(year) for year in selected_years]


def process_url(download_url: str, path: str):
    try:
        request = _retrieve_url(download_url)
        zipped_data = ZipFile(BytesIO(request.content))
    except RequestException as exception:
        raise CveLookupException(f'URL {download_url} not found. URL might have changed.') from exception
    except BadZipFile as exception:
        raise CveLookupException(f'Could not retrieve file from URL {download_url} (bad zip file)') from exception

    zipped_data.extractall(path)


@retry(RequestException, tries=3, delay=5, backoff=2)
def _retrieve_url(download_url):
    return requests.get(download_url, allow_redirects=True)


def download_cve(download_path: str, years: Optional[List[int]] = None, update: bool = False):
    if update:
        process_url(CVE_URL.format('modified'), download_path)
    else:
        all_cve_urls = get_cve_links(CVE_URL, years)
        if not all_cve_urls:
            raise CveLookupException('Error: No CVE links found')
        for url in all_cve_urls:
            process_url(url, download_path)


def download_cpe(download_path: str):
    if not CPE_URL:
        raise CveLookupException('Error: No CPE URL provided. Check metadata.json if required URL is set.')
    process_url(CPE_URL, download_path)


def extract_cpe_data_from_cve(nodes: List[dict]) -> List[Tuple[str, str, str, str, str]]:
    cpe_entries = []
    for dicts in nodes:
        if 'cpe_match' in dicts.keys():
            for cpe in dicts['cpe_match']:
                if 'cpe23Uri' in cpe and cpe['vulnerable']:
                    cpe_entries.append(
                        (
                            cpe['cpe23Uri'],
                            cpe.get('versionStartIncluding', ''),
                            cpe.get('versionStartExcluding', ''),
                            cpe.get('versionEndIncluding', ''),
                            cpe.get('versionEndExcluding', ''),
                        )
                    )
        elif 'children' in dicts.keys():
            cpe_entries.extend(extract_cpe_data_from_cve(dicts['children']))
    return cpe_entries


def extract_cve_impact(entry: dict) -> dict:
    if not entry:
        return {}
    impact = {}
    for version in [2, 3]:
        metric_key = f'baseMetricV{version}'
        cvss_key = f'cvssV{version}'
        if metric_key in entry and cvss_key in entry[metric_key]:
            impact[cvss_key] = entry[metric_key][cvss_key]['baseScore']
    return impact


def extract_data_from_cve(root: dict) -> Tuple[List[CveEntry], List[CveSummaryEntry]]:
    cve_list, summary_list = [], []
    for feed in root['CVE_Items']:
        cve_id = feed['cve']['CVE_data_meta']['ID']
        summary = feed['cve']['description']['description_data'][0]['value']
        impact = extract_cve_impact(feed['impact']) if 'impact' in feed else {}
        if feed['configurations']['nodes']:
            cpe_entries = list(set(extract_cpe_data_from_cve(feed['configurations']['nodes'])))
            cve_list.append(CveEntry(cve_id=cve_id, impact=impact, cpe_list=cpe_entries))
        elif not summary.startswith('** REJECT **'):
            summary_list.append(CveSummaryEntry(cve_id=cve_id, summary=summary, impact=impact))
    return cve_list, summary_list


def extract_cve(cve_file: str) -> Tuple[List[CveEntry], List[CveSummaryEntry]]:
    return extract_data_from_cve(json.loads(Path(cve_file).read_text()))


def extract_cpe(file: str) -> list:
    try:
        tree = parse(file)
    except ParseError as error:
        raise CveLookupException(f'could not extract CPE file: {file}') from error
    return [item.attrib['name'] for entry in tree.getroot() for item in entry if 'cpe23-item' in item.tag]
