import sys
import json
import lzma
import requests
from retry import retry
from pathlib import Path
from requests.models import Response
from requests.exceptions import RequestException

try:
    from ..internal.helper_functions import CveEntry
except (ImportError, SystemError):
    sys.path.append(str(Path(__file__).parent.parent / 'internal'))
    from helper_functions import CveEntry

FILE_NAME = 'CVE-all.json.xz'
CVE_URL = f'https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/{FILE_NAME}'


@retry(RequestException, tries=3, delay=5, backoff=2)
def _retrieve_url(download_url: str) -> Response:
    return requests.get(download_url, allow_redirects=True)


def download_and_decompress_data() -> bytes:
    """
    Downloads data from a URL, saves it to a file, decompresses it, and returns the decompressed data.
    """
    response = _retrieve_url(CVE_URL)
    file_path = Path(FILE_NAME)
    file_path.write_bytes(response.content)

    with lzma.open(file_path) as f:
        decompressed_data = f.read()

    file_path.unlink()

    return decompressed_data


def extract_english_summary(descriptions: list) -> str:
    for description in descriptions:
        if description['lang'] == 'en':
            summary = description['value']
            if not summary.startswith('** REJECT **'):
                return summary
    return ''


def extract_cve_impact(metrics: dict) -> dict[str, str]:
    impact = {}
    for version in [2, 30, 31]:
        cvss_key = f'cvssMetricV{version}'
        if cvss_key in metrics:
            for entry in metrics[cvss_key]:
                if entry['type'] == 'Primary':
                    impact.setdefault(cvss_key, entry['cvssData']['baseScore'])
                elif cvss_key not in impact:
                    impact[cvss_key] = entry['cvssData']['baseScore']
    return impact


def extract_cpe_data(configurations: list) -> list[tuple[str, str, str, str, str]]:
    unique_criteria = {}
    cpe_entries = []
    for configuration in configurations:
        for node in configuration['nodes']:
            if 'cpeMatch' in node:
                for cpe in node['cpeMatch']:
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


def parse_data() -> list[CveEntry]:
    """
    Parse the data from the JSON file and return a list of CveEntry objects.
    """
    cve_json = json.loads(download_and_decompress_data())
    return [extract_data_from_cve(cve_item) for cve_item in cve_json.get('cve_items', [])]


if __name__ == '__main__':
    parse_data()
