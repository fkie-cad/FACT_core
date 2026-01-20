from __future__ import annotations

import lzma
import re
from pathlib import Path
from typing import Iterable

import ijson
import requests
from requests.adapters import HTTPAdapter, Retry

from ..internal.helper_functions import CveEntry, is_ci

# Hack: if this is running on the CI, only load recent CVE entries instead of all
FILE_NAME = 'CVE-all.json.xz' if not is_ci() else 'CVE-recent.json.xz'
CVE_URL = f'https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/{FILE_NAME}'
DB_DIR = Path(__file__).parent / 'database'
OUTPUT_FILE = DB_DIR / FILE_NAME


def _retrieve_url(download_url: str, target: Path):
    adapter = HTTPAdapter(max_retries=Retry(total=5, backoff_factor=0.1))
    with requests.Session() as session:
        session.mount('http://', adapter)
        with requests.get(download_url, stream=True) as request:
            request.raise_for_status()
            with target.open('wb') as fp:
                for chunk in request.iter_content(chunk_size=65_536):
                    fp.write(chunk)


def extract_english_summary(descriptions: list) -> str:
    for description in descriptions:
        if description['lang'] == 'en':
            summary = description['value']
            if not summary.startswith('** REJECT **'):
                return summary
    return ''


def extract_cve_impact(metrics: dict) -> dict[str, str]:
    impact = {}
    for cvss_type, cvss_data in metrics.items():
        key = cvss_type.replace('cvssMetric', '')
        if re.match(r'V\d\d', key):
            # V30 / V31 / V40 -> V3.0 / V3.1 / V4.0
            key = f'{key[:2]}.{key[2:]}'
        for cvss_dict in cvss_data:
            score = str(cvss_dict['cvssData']['baseScore'])
            if cvss_dict['type'] == 'Primary' or key not in impact:
                impact[key] = score
    return impact


def extract_cpe_data(configurations: list) -> list[tuple[str, str, str, str, str]]:
    unique_criteria = {}
    cpe_entries = []
    for configuration in configurations:
        for node in configuration.get('nodes', []):
            for cpe in node.get('cpeMatch', []):
                if 'criteria' in cpe and cpe['vulnerable'] and cpe['criteria'] not in unique_criteria:
                    cpe_entries.append(
                        (
                            cpe['criteria'],
                            cpe.get('versionStartIncluding', ''),
                            cpe.get('versionStartExcluding', ''),
                            cpe.get('versionEndIncluding', ''),
                            cpe.get('versionEndExcluding', ''),
                        )
                    )
                    unique_criteria[cpe['criteria']] = True
    return cpe_entries


def extract_data_from_cve(cve_item: dict) -> CveEntry:
    cve_id = cve_item['id']
    summary = extract_english_summary(cve_item['descriptions'])
    impact = extract_cve_impact(cve_item['metrics'])
    cpe_entries = extract_cpe_data(cve_item.get('configurations', []))
    return CveEntry(cve_id=cve_id, summary=summary, impact=impact, cpe_entries=cpe_entries)


def parse_data() -> Iterable[CveEntry]:
    """
    Parse the data from the JSON file and return a list of CveEntry objects.
    """
    _retrieve_url(CVE_URL, OUTPUT_FILE)
    # the downloaded file is a xz archive, so we use lzma to open it:
    with lzma.open(OUTPUT_FILE, 'r') as fp:
        # inside the archive is a huge JSON file, so we use ijson to stream the data
        for cve_item in ijson.items(fp, 'cve_items.item'):
            yield extract_data_from_cve(cve_item)
    OUTPUT_FILE.unlink()  # remove the temporary file after we are done
