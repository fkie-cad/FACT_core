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
    from ..internal.helper_functions import unbind
except ImportError:
    sys.path.append(str(Path(__file__).parent.parent / 'internal'))
    from helper_functions import unbind

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
            raise RuntimeError('Error: URLs are invalid. URL format might have been changed or website might have moved. ')

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


def iterate_nodes(nodes: List[dict]) -> List[str]:
    cpe_entries = []
    for dicts in nodes:
        if 'cpe_match' in dicts.keys():
            for cpe in dicts['cpe_match']:
                if cpe['vulnerable'] is True:
                    cpe_entries.append(cpe['cpe23Uri'])
        elif 'children' in dicts.keys():
            cpe_entries.extend(iterate_nodes(dicts['children']))
    return cpe_entries


def extract_data_from_cve(root: dict) -> Tuple[list, list]:
    cve_list, summary_list = list(), list()
    for feed in root['CVE_Items']:
        cve_id = feed['cve']['CVE_data_meta']['ID']
        summary = feed['cve']['description']['description_data'][0]['value']
        if feed['configurations']['nodes']:
            cve_list.append(cve_id)
            cpe_entries = list(set(iterate_nodes(feed['configurations']['nodes'])))
            cve_list.extend(cpe_entries)
        elif not summary.startswith('** REJECT **'):
            summary_list.extend([cve_id, summary])

    return cve_list, summary_list


def extract_cve(cve_file: str) -> Tuple[list, list]:
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


def setup_cve_feeds_table(cve_list: list) -> list:
    cve_table, row = list(), list()
    ident = ''

    for entry in cve_list:
        if re.match(r'CVE-[0-9]{4}-[0-9]', entry):
            ident = entry
        else:
            row.append(ident)
            year = ident.split('-')[1]
            row.append(year)
            row.append(entry)
            row.extend(unbind(re.split(SPLIT_REGEX, entry)[2:]))
            cve_table.append(tuple(row))
            row = list()

    return cve_table


def setup_cve_summary_table(summary_list: list) -> list:
    cve_summary_table, row = list(), list()

    for entry in summary_list:
        if re.match(r'CVE-[0-9]{4}-[0-9]', entry):
            row.append(entry)
            year = entry.split('-')[1]
            row.append(year)
        else:
            row.append(entry)
            cve_summary_table.append(tuple(row))
            row = list()

    return cve_summary_table


def setup_cpe_table(cpe_list: list) -> list:
    cpe_table = []
    for cpe in cpe_list:
        row = unbind(re.split(SPLIT_REGEX, cpe)[2:])
        row.insert(0, cpe)
        cpe_table.append(tuple(row))

    return cpe_table
