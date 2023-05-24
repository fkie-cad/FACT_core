import re
import logging
import requests
from pathlib import Path
from typing import Dict, List
from objects.file import FileObject

GROUP_1 = None
GROUP_2 = None

def filter_busybox_cves(file_object: FileObject, cve_candidates: Dict[str, Dict[str, str]], version: str) -> Dict[str, Dict[str, str]]:
    '''
    Filters the BusyBox CVEs based on the components present in the binary file and the specified version.
    '''
    cves = get_cves_for_busybox_version(version)
    components = get_busybox_components(file_object)
    filtered_cves = filter_cves_by_component(cves, components)
    return {cve_id: cve_data for cve_id, cve_data in cve_candidates.items() if cve_id in filtered_cves}

def get_cves_for_busybox_version(version: str) -> Dict[str, str]:
        '''
        Gets the CVEs for the specified version of BusyBox.
        '''
        url = f'https://services.nvd.nist.gov/rest/json/cves/1.0?cpeMatchString=cpe:/a:busybox:busybox:{version}'
        try:
            response = requests.get(url)
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            logging.exception(f"Error fetching CVE data for BusyBox {version}")
            return {}

        cve_data = response.json()
        return {
            entry['cve']['CVE_data_meta']['ID']: entry['cve']['description']['description_data'][0]['value']
            for entry in cve_data['result']['CVE_Items']
        }

def get_busybox_components(file_object: FileObject) -> list[str]:
    '''
    Extracts the BusyBox components from the binary file.
    '''
    file_path = Path(file_object.file_path)
    with file_path.open(mode='rb') as f:
        data = f.read()

    start_index = data.index(b'\x5b\x00\x5b\x5b\x00')
    end_index = data.index(b'\x00\x00', start_index + 5)
    extracted_bytes = data[start_index:end_index+2]
    split_bytes = extracted_bytes.split(b'\x00')
    components = [word.decode('ascii') for word in split_bytes if word]
    return components


def filter_cves_by_component(cves: Dict[str, str], components: List[str]) -> Dict[str, List[str]]:
    '''
    Filters CVEs based on the components present in the BusyBox binary file.
    '''
    filtered_cves = {}
    for cve_id, cve_data in cves.items():
        matched_words = get_matched_words(cve_data)
        if matched_words:
            filtered_cves[cve_id] = matched_words
        else:
            filtered_cves[cve_id] = ['General CVE']

    return remove_unrelated_cves(filtered_cves, components)


def get_matched_words(cve_data: str) -> List[str]:
    '''
    Gets the matched words in the provided CVE description.
    '''
    global GROUP_1, GROUP_2

    if GROUP_1 is None or GROUP_2 is None:
        group_1_path = Path(__file__).parent / 'group_1.txt'
        group_2_path = Path(__file__).parent / 'group_2.txt'
        with group_1_path.open('r') as f1, group_2_path.open('r') as f2:
            GROUP_1 = f1.read().splitlines()
            GROUP_2 = f2.read().splitlines()

    pattern_1 = r'(?:\")(?:\-|\")'
    pattern_2 = r'(?:\b|\(|\"|\_)(?:{})(?:\b|\)|-)'

    return [word for word in GROUP_1 if re.search(pattern_1.format(word), cve_data)] + \
                    [word for word in GROUP_2 if re.search(pattern_2.format(word), cve_data)]


def remove_unrelated_cves(cves: Dict[str, List[str]], components: List[str]) -> Dict[str, List[str]]:
    '''
    Removes CVEs unrelated to the components present in the BusyBox binary file.
    '''
    filtered_cves = {}

    for cve_id, cve_data in cves.items():
        if 'General CVE' in cve_data or any(word in components for word in cve_data):
            filtered_cves[cve_id] = cve_data

    num_deleted = len(cves) - len(filtered_cves)
    if num_deleted > 0:
        logging.info(f'Deleted {num_deleted} CVEs with components not found in this BusyBox binary')

    return filtered_cves
