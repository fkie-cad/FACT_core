import re
import logging
from pathlib import Path
from typing import Dict

from .database.schema import Cve
from objects.file import FileObject

BASE_DIR = Path(__file__).parent
GROUP_1_PATH = BASE_DIR / 'group_1.txt'
GROUP_2_PATH = BASE_DIR / 'group_2.txt'

with GROUP_1_PATH.open('r') as f1, GROUP_2_PATH.open('r') as f2:
    GROUP_1 = f1.read().splitlines()
    GROUP_2 = f2.read().splitlines()

PATTERNS_1 = [re.compile(fr'(?:\")(?:{re.escape(word)})(?:\-|\")') for word in GROUP_1]
PATTERNS_2 = [re.compile(fr'(?:\b|\_)(?:{re.escape(word)})(?:\b|-)') for word in GROUP_2]


def filter_busybox_cves(file_object: FileObject, cves: Dict[str, Cve]) -> dict[str, Cve]:
    """
    Filters the BusyBox CVEs based on the components present in the binary file and the specified version.
    """
    components = get_busybox_components(file_object)
    return filter_cves_by_component(file_object, cves, components)


def get_busybox_components(file_object: FileObject) -> list[str]:
    """
    Extracts the BusyBox components from the binary file.
    """
    data = Path(file_object.file_path).read_bytes()
    start_index = data.index(b'\x5b\x00\x5b\x5b\x00')
    end_index = data.index(b'\x00\x00', start_index + 5)
    extracted_bytes = data[start_index : end_index + 2]
    split_bytes = extracted_bytes.split(b'\x00')
    return [word.decode('ascii') for word in split_bytes if word]


def filter_cves_by_component(file_object: FileObject, cves: Dict[str, Cve], components: list[str]) -> dict[str, Cve]:
    """
    Filters CVEs based on the components present in the BusyBox binary file.
    """
    filtered_cves = {}
    for cve_id, cve in cves.items():
        matched_words = get_matched_words(cve.summary)
        if not matched_words or any(word in components for word in matched_words):
            filtered_cves[cve_id] = cve

    num_deleted = len(cves) - len(filtered_cves)
    if num_deleted > 0:
        logging.debug(f'{file_object}: Deleted {num_deleted} CVEs with components not found in this BusyBox binary')

    return filtered_cves


def get_matched_words(cve_data: str) -> list[str]:
    """
    Gets the matched words in the provided CVE description.
    """
    matched_words = []
    for pattern in PATTERNS_1 + PATTERNS_2:
        match = pattern.search(cve_data)
        if match:
            matched_words.append(match.group())

    return matched_words
