import json
import logging
import re
import sys
from datetime import datetime
from io import BytesIO
from pathlib import Path
from typing import List, Tuple
from xml.etree.ElementTree import ParseError, parse
from zipfile import ZipFile

import requests

try:
    from ..internal.helper_functions import unbind, CveEntry, CveSummaryEntry
except (ImportError, SystemError):
    sys.path.append(str(Path(__file__).parent.parent / 'internal'))
    from helper_functions import unbind, CveEntry, CveSummaryEntry

CPE_FILE = 'official-cpe-dictionary_v2.3.xml'
CPE_URL = 'https://nvd.nist.gov/feeds/xml/cpe/dictionary/{}.zip'.format(CPE_FILE)
CVE_URL = 'https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-{}.json.zip'

SPLIT_REGEX = r'(?<!\\)[:]'


def get_cve_links(url: str) -> list:
    cve_urls = list()
    current = datetime.today().year
    for year in range(2002, current + 1):
        cve_urls.append(url.format(year))

    return cve_urls


def iterate_urls(download_urls: list, path: str):
    for url in download_urls:
        try:
            request = requests.get(url, allow_redirects=True)
        except requests.exceptions.RequestException:
            raise RuntimeError(
                'Error: URLs are invalid. URL format might have been changed or website might have moved. ')

        zipped_data = ZipFile(BytesIO(request.content))
        zipped_data.extractall(path)


def download_cve(update: bool, download_path: str, years: list):
    if update:
        cve_candidates = [CVE_URL.format('modified')]
    else:
        all_cve_urls = get_cve_links(CVE_URL)
        if not all_cve_urls:
            logging.error('Error: No CVE links are provided')
            sys.exit(1)
        cve_candidates = [url for url in all_cve_urls for year in years if str(year) in url]

    iterate_urls(cve_candidates, download_path)


def download_cpe(download_path: str):
    if not CPE_URL:
        logging.error('Error: No CPE URL provided. Check metadata.json if required URL is set.')
        sys.exit(1)
    iterate_urls([CPE_URL], download_path)


def extract_cpe_data_from_cve(nodes: List[dict]) -> List[Tuple[str, str, str, str, str]]:
    cpe_entries = []
    for dicts in nodes:
        if 'cpe_match' in dicts.keys():
            for cpe in dicts['cpe_match']:
                if cpe['vulnerable'] is True:
                    cpe_entries.append((
                        cpe['cpe23Uri'], cpe.get('versionStartIncluding', ''), cpe.get('versionStartExcluding', ''),
                        cpe.get('versionEndIncluding', ''), cpe.get('versionEndExcluding', '')
                    ))
        elif 'children' in dicts.keys():
            cpe_entries.extend(extract_cpe_data_from_cve(dicts['children']))
    return cpe_entries


def extract_cve_impact(entry: dict) -> dict:
    if not entry:
        return {}
    impact = {}
    for version in [2, 3]:
        metric_key = 'baseMetricV{}'.format(version)
        cvss_key = 'cvssV{}'.format(version)
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
    cpe_list = []

    try:
        tree = parse(file)
    except ParseError as error:
        logging.error(error)
        sys.exit(1)
    root = tree.getroot()

    for entry in root:
        for item in entry:
            if 'cpe23-item' in item.tag:
                cpe_list.append(item.attrib['name'])

    return cpe_list


def setup_cve_feeds_table(cve_list: List[CveEntry]) -> List[Tuple[str, ...]]:
    cve_table = []
    for entry in cve_list:
        for cpe_id, version_start_including, version_start_excluding, version_end_including, version_end_excluding in entry.cpe_list:
            year = entry.cve_id.split('-')[1]
            score_v2 = entry.impact.get('cvssV2', 'N/A')
            score_v3 = entry.impact.get('cvssV3', 'N/A')
            cpe_elements = unbind(re.split(SPLIT_REGEX, cpe_id)[2:])
            row = (
                entry.cve_id, year, cpe_id, score_v2, score_v3, *cpe_elements,
                version_start_including, version_start_excluding, version_end_including, version_end_excluding
            )
            cve_table.append(row)
    return cve_table


def setup_cve_summary_table(summary_list: List[CveSummaryEntry]) -> List[Tuple[str, ...]]:
    cve_summary_table = []
    for entry in summary_list:
        year = entry.cve_id.split('-')[1]
        score_v2 = entry.impact.get('cvssV2', 'N/A')
        score_v3 = entry.impact.get('cvssV3', 'N/A')
        cve_summary_table.append((entry.cve_id, year, entry.summary, score_v2, score_v3))
    return cve_summary_table


def setup_cpe_table(cpe_list: list) -> list:
    cpe_table = []
    for cpe in cpe_list:
        row = unbind(re.split(SPLIT_REGEX, cpe)[2:])
        row.insert(0, cpe)
        cpe_table.append(tuple(row))
    return cpe_table
